package com.identicum.keycloak;

import com.google.auto.service.AutoService;

import org.keycloak.component.ComponentValidationException;
import org.keycloak.Config.Scope;
import org.keycloak.common.util.MultivaluedHashMap;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.jboss.logging.Logger.getLogger;
import static org.keycloak.models.credential.PasswordCredentialModel.TYPE;

import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;

import static com.identicum.keycloak.Configuration.API_CONNECTION_REQUEST_TIMEOUT;
import static com.identicum.keycloak.Configuration.API_CONNECT_TIMEOUT;
import static com.identicum.keycloak.Configuration.API_SOCKET_TIMEOUT;
import static com.identicum.keycloak.Configuration.PROPERTY_BASE_URL;
import static com.identicum.keycloak.Configuration.PROPERTY_MAX_HTTP_CONNECTIONS;
import static com.identicum.keycloak.Configuration.validate;
import static org.jboss.logging.Logger.getLogger;
import static org.keycloak.provider.ProviderConfigProperty.LIST_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.PASSWORD;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class KeycloakRestRepoProvider implements CredentialInputValidator,
												 UserStorageProvider,
												 UserLookupProvider,
												 UserQueryProvider {

	private static final Logger logger = getLogger(KeycloakRestRepoProvider.class);

	protected KeycloakSession session;
	protected ComponentModel model;

	// map of loaded users in this transaction
	protected Map<String, RestUserAdapter> loadedUsers = new HashMap<>();

	protected RestHandler restHandler;

	public KeycloakRestRepoProvider(KeycloakSession session, ComponentModel model, RestHandler restHandler) {
		logger.info("Initializing new RestRepoProvider");
		this.session = session;
		this.model = model;
		this.restHandler = restHandler;
	}

	@Override
	public void close() {
	}

	@Override
	public UserModel getUserByEmail(RealmModel realm, String email) {
		logger.infov("Getting user: {0} by email", email);
		return this.getUser(email, realm);
	}

	@Override
	public UserModel getUserById(RealmModel realm, String id) {
		logger.infov("Getting user by id: {0}", id);
		return this.getUser(StorageId.externalId(id), realm);
	}

	@Override
	public UserModel getUserByUsername(RealmModel realm, String username) {
		logger.infov("Getting user: {0} by username", username);
		return this.getUser(username, realm);
	}

	private UserModel getUser(String query, RealmModel realm) {
		logger.debugv("Cache size is: {0}", loadedUsers.size());

		RestUserAdapter adapter = loadedUsers.get(query);
		if (adapter == null) {
			JsonObject userJson = this.restHandler.findUserByUsername(query);
			if (userJson == null) {
				logger.debugv("User {0} not found in repo", query);
				return null;
			}
			adapter = new RestUserAdapter(session, realm, model, userJson);
			adapter.setHandler(this.restHandler);
		} else {
			logger.debugv("Returning user {0} from cache", query);
		}
		return adapter;
	}

	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
		return credentialType.equals(TYPE);
	}

	/**
	 * Método que finalmente controla las credenciales
	 */
	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
		logger.infov("Validating user {0}", user.getUsername());
		if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) return false;
		logger.infov("Credential {0}", input.getChallengeResponse());
		return restHandler.authenticate(user.getUsername(), input.getChallengeResponse());
	}

	/**
	 * Indica qué tipo de credenciales puede validar, por ejemplo Password
	 */
	@Override
	public boolean supportsCredentialType(String credentialType) {
		return credentialType.equals(TYPE);
	}

	@Override
	public int getUsersCount(RealmModel realmModel) {
		return 0;
	}

	@Override
	public Stream<UserModel> getGroupMembersStream(RealmModel arg0, GroupModel arg1, Integer arg2, Integer arg3) {
		return Stream.empty();
	}

	@Override
	public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String attributeName, String attributeValue) {
		return Stream.empty();
	}

	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realmModel, Map<String, String> params, Integer firstResult, Integer maxResults) {
		logger.infov("Searching users {0}", params);
		String query = params.get("keycloak.session.realm.users.query.search");
	
		logger.infov("Searching users with query: {0} from {1} with maxResults {2}", query, firstResult, maxResults);
		JsonArray usersJson = restHandler.findUsers(query);
		logger.infov("Found {0} users", usersJson.size());
	
		return IntStream.range(firstResult, Math.min(usersJson.size(), firstResult + maxResults))
				.mapToObj(i -> {
					logger.infov("Converting user {0} to UserModel", usersJson.getJsonObject(i));
					RestUserAdapter userModel = new RestUserAdapter(session, realmModel, model, usersJson.getJsonObject(i));
					userModel.setHandler(restHandler);
					return userModel;
				});
	}

	@AutoService(UserStorageProviderFactory.class)
	public static class KeycloakRestRepoProviderFactory implements UserStorageProviderFactory<KeycloakRestRepoProvider> {
	
		private static final Logger logger = getLogger(KeycloakRestRepoProviderFactory.class);
		private List<ProviderConfigProperty> configMetadata;
		private MultivaluedHashMap<String, String> lastConfiguration = null;
	
		private RestHandler restHandler;
	
		@Override
		public void init(Scope config) {
			logger.infov("Initializing Keycloak Rest Repo factory version: " + getClass().getPackage().getImplementationVersion());
	
			ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();
			builder.property().name(PROPERTY_BASE_URL)
					.type(STRING_TYPE).label("Base URL")
					.defaultValue("http://rest-users-api:8081/")
					.helpText("Api url base to authenticate users")
					.add();
			builder.property().name(PROPERTY_MAX_HTTP_CONNECTIONS)
					.type(STRING_TYPE).label("Max pool connections")
					.defaultValue("5")
					.helpText("Max http connections in pool")
					.add();
			builder.property().name(API_SOCKET_TIMEOUT)
					.type(STRING_TYPE).label("API Socket Timeout")
					.defaultValue("1000")
					.helpText("Max time [milliseconds] to wait for response")
					.add();
			builder.property().name(API_CONNECT_TIMEOUT)
					.type(STRING_TYPE).label("API Connect Timeout")
					.defaultValue("1000")
					.helpText("Max time [milliseconds] to establish the connection")
					.add();
			builder.property().name(API_CONNECTION_REQUEST_TIMEOUT)
					.type(STRING_TYPE).label("API Connection Request Timeout")
					.defaultValue("1000")
					.helpText("Max time [milliseconds] to wait until a connection in the pool is assigned to the requesting thread")
					.add();
			configMetadata = builder.build();
		}
	
		@Override
		public KeycloakRestRepoProvider create(KeycloakSession session, ComponentModel model) {
			if(restHandler == null || !model.getConfig().equals( lastConfiguration )) {
				logger.infov("Creating a new instance of restHandler");
				Configuration configuration = new Configuration(model.getConfig());
				restHandler = new RestHandler(configuration);
				lastConfiguration = model.getConfig();
			} else {
				logger.infov("RestHandler already instantiated");
			}
			return new KeycloakRestRepoProvider(session, model, restHandler);
		}
	
		@Override
		public String getId() {
			return "rest-repo-provider";
		}
	
		@Override
		public List<ProviderConfigProperty> getConfigProperties() {
			return configMetadata;
		}
	
		@Override
		public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {
			validate(config.getConfig());
		}
	}

}