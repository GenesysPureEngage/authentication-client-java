package com.genesys.authentication;

import com.genesys.internal.authentication.model.*;
import com.genesys.internal.common.*;
import com.google.gson.reflect.TypeToken;
import com.squareup.okhttp.Call;
import com.squareup.okhttp.Headers;
import com.squareup.okhttp.Request;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;

public class AuthenticationApi {

    private ApiClient client;

    private com.genesys.internal.authentication.api.AuthenticationApi authenticationApi;

    private final RetrieveTokenApi retrieveToken;

    private final AuthorizationApi authorization;

    /**
     * Create a AuthenticationApi object with your given authentication base URI and API key.
     *
     * @param baseUri authentication base URI.
     * @param apiKey  your API key.
     */
    public AuthenticationApi(String baseUri, String apiKey) {
        client = new ApiClient();
        client.setBasePath(baseUri);
        client.setApiKey(apiKey);
        retrieveToken = new RetrieveTokenApi(client);
        authorization = new AuthorizationApi(client);
        authenticationApi = new com.genesys.internal.authentication.api.AuthenticationApi(client);
    }

    /**
     * The authorization object contains API requests to perform authorization.
     */
    public AuthorizationApi getAuthorization() {
        return authorization;
    }

    /**
     * The retrieveToken object contains API requests to retrieve access token.
     */
    public RetrieveTokenApi getRetrieveToken() {
        return retrieveToken;
    }

    /**
     * Change password
     * Change the user&#39;s password.
     *
     * @param request       request (required)
     * @param authorization The OAuth 2 bearer access token you received from [/auth/v3/oauth/token](/reference/authentication/Authentication/index.html#retrieveToken). For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;  (optional, default to bearer)
     * @return ModelApiResponse
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public ModelApiResponse changePassword(ChangePasswordOperation request, String authorization) throws AuthenticationApiException {
        try {
            return authenticationApi.changePassword(request, authorization);
        } catch (ApiException e) {
            throw new AuthenticationApiException("Error changing password", e);
        }
    }

    /**
     * Check connection
     * Return 200 if user is authenticated otherwise 403
     *
     * @return ModelApiResponse
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public ModelApiResponse ping() throws AuthenticationApiException {
        try {
            return authenticationApi.ping();
        } catch (ApiException e) {
            throw new AuthenticationApiException("Error during keep alive ping", e);
        }
    }

    /**
     * Get user information by access token
     * Get information about a user by their OAuth 2 access token.
     *
     * @param authorization The OAuth 2 bearer access token. For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;  (required)
     * @return CloudUserDetails
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public CloudUserDetails getUserInfo(String authorization) throws AuthenticationApiException {
        try {
            return authenticationApi.getInfo1(authorization);
        } catch (ApiException e) {
            throw new AuthenticationApiException("Error getting userinfo", e);
        }
    }

    /**
     * Get OpenID user information by access token
     * Get information about a user by their OAuth 2 access token.
     *
     * @param authorization The OAuth 2 bearer access token you received from [/auth/v3/oauth/token](/reference/authentication/Authentication/index.html#retrieveToken). For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;  (required)
     * @return OpenIdUserInfo
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public OpenIdUserInfo getUserInfoOpenid(String authorization) throws AuthenticationApiException {
        try {
            return authenticationApi.getInfo(authorization);
        } catch (ApiException e) {
            throw new AuthenticationApiException("Error getting openid userinfo", e);
        }
    }

    /**
     * getJwtInfo
     *
     * @return ModelApiResponse
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public ModelApiResponse getJwtUserInfo() throws AuthenticationApiException {
        try {
            return authenticationApi.getJwtInfoUsingGET();
        } catch (ApiException e) {
            throw new AuthenticationApiException("Error getting jwt userinfo", e);
        }
    }

    /**
     * Sign-out a logged in user
     * Sign-out the current user and invalidate either the current token or all tokens associated with the user.
     *
     * @param authorization The OAuth 2 bearer access token you received from [/auth/v3/oauth/token](/reference/authentication/Authentication/index.html#retrieveToken). For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;  (required)
     * @param global        Specifies whether to invalidate all tokens for the current user (&#x60;true&#x60;) or only the current token (&#x60;false&#x60;). (optional)
     * @param redirectUri   Specifies the URI where the browser is redirected after sign-out is successful. (optional)
     * @return ModelApiResponse
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public ModelApiResponse signOutGet(String authorization, Boolean global, String redirectUri) throws AuthenticationApiException {
        try {
            return authenticationApi.signOut1(authorization, global, redirectUri);
        } catch (ApiException e) {
            throw new AuthenticationApiException("Error sign out", e);
        }
    }

    /**
     * Sign-out a logged in user
     * Sign-out the current user and invalidate either the current token or all tokens associated with the user.
     *
     * @param authorization The OAuth 2 bearer access token you received from [/auth/v3/oauth/token](/reference/authentication/Authentication/index.html#retrieveToken). For example: \&quot;Authorization: bearer a4b5da75-a584-4053-9227-0f0ab23ff06e\&quot;  (required)
     * @param global        Specifies whether to invalidate all tokens for the current user (&#x60;true&#x60;) or only the current token (&#x60;false&#x60;). (optional)
     * @return ModelApiResponse
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public ModelApiResponse signOutPost(String authorization, Boolean global) throws AuthenticationApiException {
        try {
            return authenticationApi.signOut(authorization, global);
        } catch (ApiException e) {
            throw new AuthenticationApiException("Error sign out", e);
        }
    }

    /**
     * Get authentication scheme.
     * Get the authentication scheme by user name or tenant name. The return value is   &#39;saml&#39; if the contact center has [Security Assertion Markup Language](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)   (SAML) enabled; otherwise, the return value is &#39;basic&#39;.
     *
     * @param lookupData Data for scheme lookup. (optional)
     * @return ModelApiResponse
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public ModelApiResponse retrieveAuthScheme(AuthSchemeLookupData lookupData) throws AuthenticationApiException {
        try {
            return authenticationApi.tenantInfo(lookupData);
        } catch (ApiException e) {
            throw new AuthenticationApiException("Error retrieve auth scheme", e);
        }
    }

    /**
     * Build  form parameters to sign in
     *
     * @param username The agent&#39;s username, formatted as &#39;tenant\\username&#39;. (required)
     * @param password The agent&#39;s password. (required)
     * @param isSaml Specifies whether to login using [Security Assertion Markup Language](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) (SAML). (optional)
     * @return a map of form parameters
     * @throws IllegalArgumentException if required form parameter is missed
     */
    public static Map<String, Object> createFormParamSignIn(String username, String password, Boolean isSaml) {
        if (username == null) {
            throw new IllegalArgumentException("Missing the required parameter 'username'");
        }
        if (password == null) {
            throw new IllegalArgumentException("Missing the required parameter 'password'");
        }
        Map<String, Object> formParams = new HashMap<>();
        formParams.put("username", username);
        formParams.put("password", password);
        if (isSaml != null) {
            formParams.put("saml", isSaml);
        }
        return formParams;
    }

    /**
     * Perform form-based authentication.
     * Perform form-based authentication by submitting an agent&#39;s username and password.
     *
     * @param formParams The form parameters, can be created via static methods
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public void signIn(Map<String, Object> formParams) throws AuthenticationApiException {
        Headers.Builder headerBuilder = new Headers.Builder();
        headerBuilder.add("Accept", "*/*");
        headerBuilder.add("Content-Type", "application/x-www-form-urlencoded");

        Request request = new Request.Builder()
                .url(client.getBasePath() + "/sign-in")
                .headers(headerBuilder.build())
                .post(client.buildRequestBodyFormEncoding(formParams))
                .build();
        try {
            this.client.getHttpClient().newCall(request).execute();
        } catch (IOException e) {
            throw new AuthenticationApiException("Authorization error", e);
        }
    }
}
