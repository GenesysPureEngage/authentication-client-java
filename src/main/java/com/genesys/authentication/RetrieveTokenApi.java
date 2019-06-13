package com.genesys.authentication;

import com.genesys.internal.authentication.model.DefaultOAuth2AccessToken;
import com.genesys.internal.common.ApiClient;
import com.genesys.internal.common.ApiException;
import com.genesys.internal.common.ApiResponse;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.Call;
import com.squareup.okhttp.Headers;
import com.squareup.okhttp.Request;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

public class RetrieveTokenApi {

    private ApiClient client;

    public RetrieveTokenApi(ApiClient client) {
        this.client = client;
    }

    /**
     * Build form parameters
     *
     * @param redirectUri Uri to redirect
     * @param code        See [Authorization code](https://tools.ietf.org/html/rfc6749#section-1.3.1) for details.
     * @param clientId    The ID of the application or service that is registered as the client. You&#39;ll need to get this value from your PureEngage Cloud representative. (optional)
     * @return a map of form parameters
     * @throws IllegalArgumentException if required form parameters are missed
     */
    public static Map<String, Object> createFormParamAuthCodeGrantType(String redirectUri, String code, String clientId) {
        if (redirectUri == null) {
            throw new IllegalArgumentException("Missing the required parameter 'redirect_uri'");
        }
        if (code == null) {
            throw new IllegalArgumentException("Missing the required parameter 'code'");
        }
        Map<String, Object> formParams = new HashMap<>();
        formParams.put("grant_type", "authorization_code");
        formParams.put("redirect_uri", redirectUri);
        formParams.put("code", code);
        if (clientId != null) {
            formParams.put("client_id", clientId);
        }
        return formParams;
    }

    /**
     * Build form parameters
     *
     * @param username The agent&#39;s username.
     * @param password The agent&#39;s password.
     * @param scope    The scope of the access request. The Authentication API supports only the &#x60;*&#x60; value. (optional)
     * @param clientId The ID of the application or service that is registered as the client. You&#39;ll need to get this value from your PureEngage Cloud representative. (optional)
     * @return a map of form parameters
     * @throws IllegalArgumentException if required form parameters are missed
     */
    public static Map<String, Object> createFormParamPasswordGrantType(String username, String password, String scope, String clientId) {
        if (username == null) {
            throw new IllegalArgumentException("Missing the required parameter 'username'");
        }
        if (password == null) {
            throw new IllegalArgumentException("Missing the required parameter 'password'");
        }
        Map<String, Object> formParams = new HashMap<>();
        formParams.put("grant_type", "password");
        formParams.put("username", username);
        formParams.put("password", password);
        if (clientId != null) {
            formParams.put("client_id", clientId);
        }
        if (scope != null) {
            formParams.put("scope", scope);
        }
        return formParams;
    }

    /**
     * Build form parameters
     *
     * @param scope The scope of the access request. The Authentication API supports only the &#x60;*&#x60; value. (optional)
     * @return a map of form parameters
     */
    public static Map<String, Object> createFormParamClientCredentialsGrantType(String scope) {
        Map<String, Object> formParams = new HashMap<>();
        formParams.put("grant_type", "client_credentials");
        if (scope != null) {
            formParams.put("scope", scope);
        }
        return formParams;
    }

    /**
     * Build form parameters
     *
     * @param refreshToken See [Refresh Token](https://tools.ietf.org/html/rfc6749#section-1.5) for details.
     * @param scope        The scope of the access request. The Authentication API supports only the &#x60;*&#x60; value. (optional)
     * @param clientId     The ID of the application or service that is registered as the client. You&#39;ll need to get this value from your PureEngage Cloud representative. (optional)
     * @return a map of form parameters
     * @throws IllegalArgumentException if required form parameter is missed
     */
    public static Map<String, Object> createFormParamRefreshTokenGrantType(String refreshToken, String scope, String clientId) {
        if (refreshToken == null) {
            throw new IllegalArgumentException("Missing the required parameter 'refresh_token'");
        }
        Map<String, Object> formParams = new HashMap<>();
        formParams.put("grant_type", "refresh_token");
        formParams.put("refresh_token", refreshToken);
        if (scope != null) {
            formParams.put("scope", scope);
        }
        if (clientId != null) {
            formParams.put("client_id", clientId);
        }
        return formParams;
    }

    /**
     * Retrieve access token
     * Retrieve an access token based on the grant type &amp;mdash; Authorization Code Grant, Resource Owner Password Credentials Grant or Client Credentials Grant. For more information, see [Token Endpoint](https://tools.ietf.org/html/rfc6749). **Note:** For the optional **scope** parameter, the Authentication API supports only the &#x60;*&#x60; value.
     *
     * @param formParams    The form parameters, can be created via static methods
     * @param authorization Basic authorization. For example: &#39;Authorization: Basic Y3...MQ&#x3D;&#x3D;&#39; (optional)
     * @return DefaultOAuth2AccessToken
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public DefaultOAuth2AccessToken retrieveToken(Map<String, Object> formParams, String authorization) throws AuthenticationApiException {
        Map<String, String> headers = new HashMap<String, String>();

        Headers.Builder headerBuilder = new Headers.Builder();
        headerBuilder.add("Accept", "*/*");
        headerBuilder.add("Content-Type", "application/x-www-form-urlencoded");
        if (authorization != null) {
            headerBuilder.add("Authorization", authorization);
        }

        Request.Builder reqBuilder = new Request.Builder()
                .url(client.getBasePath() + "/oauth/token")
                .headers(headerBuilder.build())
                .post(client.buildRequestBodyFormEncoding(formParams));
        client.processHeaderParams(headers, reqBuilder);

        Request request = reqBuilder.build();
        Call call = client.getHttpClient().newCall(request);
        Type returnType = new TypeToken<DefaultOAuth2AccessToken>() {
        }.getType();
        try {
            ApiResponse<DefaultOAuth2AccessToken> resp = client.execute(call, returnType);
            return resp.getData();
        } catch (ApiException e) {
            throw new AuthenticationApiException("Authorization error", e);
        }
    }
}
