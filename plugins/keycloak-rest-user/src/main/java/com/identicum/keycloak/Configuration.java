package com.identicum.keycloak;

import lombok.Getter;
import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentValidationException;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

import static java.lang.Integer.parseInt;

@Getter
public class Configuration {

	public static final String PROPERTY_BASE_URL = "baseURL";
	public static final String PROPERTY_MAX_HTTP_CONNECTIONS = "maxHttpConnections";
	public static final String API_SOCKET_TIMEOUT = "apiSocketTimeout";
	public static final String API_CONNECT_TIMEOUT = "apiConnectTimeout";
	public static final String API_CONNECTION_REQUEST_TIMEOUT = "apiConnectionRequestTimeout";

	private static final Logger logger = Logger.getLogger(Configuration.class);

	private String baseUrl;
	private Integer maxConnections;
	private Integer apiSocketTimeout;
	private Integer apiConnectTimeout;
	private Integer apiConnectionRequestTimeout;

	public Configuration(MultivaluedHashMap<String, String> keycloakConfig) {
		this.baseUrl = keycloakConfig.getFirst(PROPERTY_BASE_URL);
		logger.infov("Loaded baseURL from module properties: {0}", baseUrl);
		if(baseUrl.endsWith("/")) {
			this.baseUrl = baseUrl.substring(0, baseUrl.length()-1);
			logger.infov("Removing trailing slash from URL: {0}", baseUrl);
		}

		this.maxConnections = parseInt(keycloakConfig.getFirst(PROPERTY_MAX_HTTP_CONNECTIONS));
		logger.infov("Loaded maxHttpConnections from module properties: {0}", maxConnections);

		this.apiSocketTimeout = parseInt(keycloakConfig.getFirst(API_SOCKET_TIMEOUT));
		logger.infov("Loaded apiSocketTimeout from module properties: {0}", apiSocketTimeout);

		this.apiConnectTimeout = parseInt(keycloakConfig.getFirst(API_CONNECT_TIMEOUT));
		logger.infov("Loaded apiConnectTimeout from module properties: {0}", apiConnectTimeout);

		this.apiConnectionRequestTimeout = parseInt(keycloakConfig.getFirst(API_CONNECTION_REQUEST_TIMEOUT));
		logger.infov("Loaded apiConnectionRequestTimeout from module properties: {0}", apiConnectionRequestTimeout);
	}

	public static void validate(MultivaluedHashMap<String, String> config) {
		String baseURL = config.getFirst(PROPERTY_BASE_URL);
		if (baseURL == null) throw new ComponentValidationException("BaseURL is not specified");
		try {
			HttpURLConnection urlConn = (HttpURLConnection) URI.create(baseURL).toURL().openConnection();
			urlConn.connect();
			urlConn.disconnect();
		} catch (IOException e) {
			throw new ComponentValidationException("Error accessing the base url", e);
		}

		String maxConnections = config.getFirst(PROPERTY_MAX_HTTP_CONNECTIONS);
		if(maxConnections == null || !maxConnections.matches("\\d*")) {
			logger.warn("maxHttpConnections property is not valid. Enter a valid number");
			throw new ComponentValidationException("Max pool connections should be a number");
		}
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("baseUrl: " + baseUrl + "; ");
		buffer.append("maxConnections: " + maxConnections + "; ");
		buffer.append("apiSocketTimeout: " + apiSocketTimeout + "; ");
		buffer.append("apiConnectTimeout: " + apiConnectTimeout + "; ");
		buffer.append("apiConnectionRequestTimeout: " + apiConnectionRequestTimeout);

		return buffer.toString();
	}
}