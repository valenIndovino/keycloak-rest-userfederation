package com.identicum.keycloak;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.ConnectionPoolTimeoutException;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.pool.PoolStats;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.ForkFlowException;
import org.keycloak.models.utils.FormMessage;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.*;

import static java.lang.Boolean.TRUE;
import static java.lang.String.format;
import static java.lang.System.currentTimeMillis;
import static java.util.stream.Stream.of;
import static jakarta.json.Json.createObjectBuilder;
import static org.apache.http.Consts.UTF_8;
import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.AUTHORIZATION;
import static org.apache.http.HttpHeaders.CONNECTION;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.apache.http.entity.ContentType.APPLICATION_FORM_URLENCODED;
import static org.apache.http.entity.ContentType.APPLICATION_JSON;
import static org.apache.http.protocol.HTTP.CONN_DIRECTIVE;
import static org.apache.http.protocol.HTTP.CONN_KEEP_ALIVE;
import static org.jboss.logging.Logger.getLogger;

public class RestHandler {

	private static final Logger logger = getLogger(RestHandler.class);
	protected CloseableHttpClient httpClient;

	private final Configuration configuration;
	private final PoolingHttpClientConnectionManager poolingHttpClientConnectionManager;

	private final String BACKEND_AUTHENTICATION_ERROR = "BACKEND_AUTHENTICATION_ERROR";

	public RestHandler(Configuration configuration) {
		Integer maxConnections = configuration.getMaxConnections();
		Integer socketTimeout = configuration.getApiSocketTimeout();
		Integer connectTimeout = configuration.getApiConnectTimeout();
		Integer connectionRequestTimeout = configuration.getApiConnectionRequestTimeout();
		logger.infov("Initializing HTTP pool with maxConnections: {0}, connectionRequestTimeout: {1}, connectTimeout: {2}, socketTimeout: {3}", maxConnections, connectionRequestTimeout, connectTimeout, socketTimeout);
		this.poolingHttpClientConnectionManager = new PoolingHttpClientConnectionManager();
		this.poolingHttpClientConnectionManager.setMaxTotal(maxConnections);
		this.poolingHttpClientConnectionManager.setDefaultMaxPerRoute(maxConnections);
		this.poolingHttpClientConnectionManager.setDefaultSocketConfig(SocketConfig.custom()
				.setSoTimeout(socketTimeout)
				.build());
		RequestConfig requestConfig = RequestConfig.custom()
				.setConnectTimeout(connectTimeout)
				.setConnectionRequestTimeout(connectionRequestTimeout)
				.build();
		this.httpClient = HttpClients.custom()
				.setDefaultRequestConfig(requestConfig)
				.setConnectionManager(poolingHttpClientConnectionManager)
				.build();
		this.configuration = configuration;
	}

	public boolean authenticate(String username, String password) {
		logger.infov("Authenticating user: {0}", username);
		HttpPost httpPost = new HttpPost(configuration.getBaseUrl() + "/authenticate");
		httpPost.setHeader(ACCEPT, APPLICATION_JSON.getMimeType());
		httpPost.setHeader(CONTENT_TYPE, APPLICATION_JSON.getMimeType());
		httpPost.setHeader(CONNECTION, CONN_KEEP_ALIVE);

		JsonObject json = createObjectBuilder()
				.add("username", username)
				.add("password", password)
				.build();
		HttpEntity entity = new ByteArrayEntity(json.toString().getBytes());
		httpPost.setEntity(entity);

		SimpleHttpResponse response = executeCall(httpPost);
		return response.isSuccess();
	}

	public JsonObject findUserByUsername(String username) {
		logger.infov("Finding user by username: {0}", username);
		SimpleHttpResponse response = executeCall(new HttpGet(configuration.getBaseUrl() + "/users/" + username));
		return response.isSuccess()? response.getResponseAsJsonObject() : null;
	}

	public void setUserAttribute(String username, String attribute, String value) {
		logger.infov("Setting user {0} attribute {1}: {2}", username, attribute, value);

		HttpPatch httpPatch = new HttpPatch(configuration.getBaseUrl() + "/users/" + username);
		httpPatch.setHeader("Content-Type", "application/json");
		JsonObject requestJson = createObjectBuilder().add(attribute, value).build();
		logger.infov("Setting patch body as: {0}", requestJson.toString());

		HttpEntity httpEntity = new ByteArrayEntity(requestJson.toString().getBytes());
		httpPatch.setEntity(httpEntity);

		stopOnError(executeCall(httpPatch));
	}

	public Map<String, Integer> getStats() {
		HashMap<String, Integer> stats = new HashMap<>();
		PoolStats poolStats = poolingHttpClientConnectionManager.getTotalStats();
		stats.put("maxConnections", poolStats.getMax());
		stats.put("defaultMaxPerRoute", poolingHttpClientConnectionManager.getDefaultMaxPerRoute());
		stats.put("availableConnections", poolStats.getAvailable());
		stats.put("leasedConnections", poolStats.getLeased());
		stats.put("pendingConnections", poolStats.getPending());
		return stats;
	}

	public JsonArray findUsers(String username) {
		logger.infov("Finding users with username: {0}", username);
		String searchUrl = configuration.getBaseUrl() + "/users";
		if(username != null) {
			searchUrl += "?username=" + username;
		}
		logger.infov("Using url {0} to search users", searchUrl);
		SimpleHttpResponse response = executeCall(new HttpGet(searchUrl));
		stopOnError(response);
		return response.getResponseAsJsonArray();
	}

	/* ------------------------------------------------------------------------ */
	/* HTTP calls handlers                                                      */
	/* ------------------------------------------------------------------------ */

	/**
	 * Close quietly a http response
	 * @param response Response to be closed
	 */
	private void closeQuietly(CloseableHttpResponse response) {
		if (response != null)
			try {
				response.close();
			} catch (IOException io) {
				logger.warn("Error closing http response", io);
			}
	}

	/**
	 * Execute http request with the connection pool and handle the received response.
	 * If the response status is not OK it throws a {@link RuntimeException} to stop the flow.
	 *
	 * @param request Request to be executed with all needed headers.
	 * @return SimpleHttpResponse with code received and body
	 * @throws RuntimeException if status code received is not 200
	 */
	private SimpleHttpResponse executeCall(HttpRequestBase request) {
		logger.debugv("Executing Http Request [{0}] on [{1}]", request.getMethod(), request.getURI());
		request.setHeader(CONNECTION, CONN_KEEP_ALIVE);

		of( request.getAllHeaders() ).forEach(header -> logger.debugv("Request header: {0} -> {1}", header.getName(), header.getValue() ));
		CloseableHttpResponse response = null;
		try {
			response = httpClient.execute(request);
			String responseString = EntityUtils.toString(response.getEntity(), "UTF-8");
			logger.debugv("Response code obtained from server: {0}", response.getStatusLine().getStatusCode());
			logger.debugv("Response body obtained from server: {0}", responseString);
			return new SimpleHttpResponse(response.getStatusLine().getStatusCode(), responseString);
		}
		catch(ConnectionPoolTimeoutException cpte) {
			logger.errorv(format("Connection pool timeout exception: %s", cpte), cpte);
			throw new ForkFlowException(new FormMessage(""), new FormMessage(BACKEND_AUTHENTICATION_ERROR));
		}
		catch(ConnectTimeoutException cte) {
			logger.errorv(format("Connect timeout exception: %s", cte), cte);
			throw new ForkFlowException(new FormMessage(""), new FormMessage(BACKEND_AUTHENTICATION_ERROR));
		}
		catch(SocketTimeoutException ste) {
			logger.errorv(format("Socket timeout exception: %s", ste), ste);
			throw new ForkFlowException(new FormMessage(""), new FormMessage(BACKEND_AUTHENTICATION_ERROR));
		}
		catch(IOException io) {
			logger.errorv(format("Error executing request: %s", io), io);
			throw new ForkFlowException(new FormMessage(""), new FormMessage(BACKEND_AUTHENTICATION_ERROR));
		}
		finally {
			closeQuietly(response);
		}
	}

	private void stopOnError(SimpleHttpResponse response) {
		if(!response.isSuccess()) {
			StringBuffer buffer = new StringBuffer();
			buffer.append("Response status code was not success. Code received: ");
			buffer.append(response.getStatus());
			buffer.append("\nResponse received: ");
			buffer.append("\n" + response.getResponse());
			buffer.append("\nHttp Request was not success. Check logs to get more information");
			logger.errorv(buffer.toString());
			throw new ForkFlowException(new FormMessage(""), new FormMessage(BACKEND_AUTHENTICATION_ERROR));
		}
	}
}