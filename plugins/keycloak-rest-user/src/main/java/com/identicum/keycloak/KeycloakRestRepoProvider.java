package com.identicum.keycloak;

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
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.identicum.keycloak.RestUserAdapter.randomPassword;
import static org.jboss.logging.Logger.getLogger;
import static org.keycloak.models.credential.PasswordCredentialModel.TYPE;

public class KeycloakRestRepoProvider implements CredentialInputValidator,
												 CredentialInputUpdater,
												 UserStorageProvider,
												 UserLookupProvider,
												 UserQueryProvider,
												 UserRegistrationProvider {

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

	public UserModel getUser(String query, RealmModel realm) {
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
	public boolean updateCredential(RealmModel realmModel, UserModel userModel, CredentialInput credentialInput) {
		restHandler.setUserAttribute(userModel.getUsername(), "password", credentialInput.getChallengeResponse());
		return true;
	}

	@Override
	public void disableCredentialType(RealmModel realmModel, UserModel userModel, String credentialType) {
		if (!supportsCredentialType(credentialType)) return;
		restHandler.setUserAttribute(userModel.getUsername(), "password", randomPassword());
	}

	@Override
	public Stream<String> getDisableableCredentialTypesStream(RealmModel realmModel, UserModel userModel) {
		Set<String> set = new HashSet<>();
		set.add(TYPE);
		return set.stream();
	}

	@Override
	public int getUsersCount(RealmModel realmModel) {
		return 0;
	}

	@Override
	public UserModel addUser(RealmModel realmModel, String username) {
		JsonObject user = restHandler.createUser(username);
		RestUserAdapter adapter = new RestUserAdapter(session, realmModel, model, user);
		adapter.setHandler(restHandler);
		logger.infov("Setting user {0} into cache", username);
		loadedUsers.put(username, adapter);
		return adapter;
	}

	@Override
	public boolean removeUser(RealmModel realmModel, UserModel userModel) {
		restHandler.deleteUser(userModel.getUsername());
		loadedUsers.remove(userModel.getUsername());
		return true;
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
}
