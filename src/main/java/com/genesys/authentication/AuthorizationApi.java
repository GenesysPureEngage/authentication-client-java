package com.genesys.authentication;

import com.genesys.internal.common.*;
import com.squareup.okhttp.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class AuthorizationApi {

    private ApiClient client;

    public AuthorizationApi(ApiClient client) {
        this.client = client;
    }

    /**
     * Build query parameters
     *
     * @param clientId     The ID of the application or service that is registered as the client. You&#39;ll need to get this value from your PureEngage Cloud representative.
     * @param redirectUri  The URI that you want users to be redirected to after entering valid credentials during an Implicit or Authorization Code grant. The Authentication API includes this as part of the URI it returns in the &#39;Location&#39; header.
     * @param responseType The response type to let the Authentication API know which grant flow you&#39;re using. Possible values are &#x60;code&#x60; for Authorization Code Grant or &#x60;token&#x60; for Implicit Grant. For more information about this parameter, see [Response Type](https://tools.ietf.org/html/rfc6749#section-3.1.1).
     * @param hideTenant   Hide the **tenant** field in the UI for Authorization Code Grant. (optional, default to false)
     * @param scope        The scope of the access request. The Authentication API supports only the &#x60;*&#x60; value. (optional)
     * @throws IllegalArgumentException if required query parameters are missed
     */
    public static Map<String, String> createQueryParamsList(String clientId, String redirectUri, String responseType, String hideTenant, String scope) {
        if (clientId == null) {
            throw new IllegalArgumentException("Missing the required parameter 'client_id'");
        }
        if (redirectUri == null) {
            throw new IllegalArgumentException("Missing the required parameter 'redirect_uri'");
        }
        if (responseType == null) {
            throw new IllegalArgumentException("Missing the required parameter 'response_type'");
        }
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("client_id", clientId);
        queryParams.put("redirect_uri", redirectUri);
        queryParams.put("response_type", responseType);
        if (hideTenant != null)
            queryParams.put("hideTenant", hideTenant);
        if (scope != null)
            queryParams.put("scope", scope);
        return queryParams;
    }

    /**
     * Perform authorization
     * Perform authorization based on the code grant type &amp;mdash; either Authorization Code Grant or Implicit Grant. For more information, see [Authorization Endpoint](https://tools.ietf.org/html/rfc6749#section-3.1). **Note:** For the optional **scope** parameter, the Authentication API supports only the &#x60;*&#x60; value.
     *
     * @param queryParams   The form parameters, can be created via static methods
     * @param authorization Basic authorization. For example: &#39;Authorization: Basic Y3...MQ&#x3D;&#x3D;&#39; (optional)
     * @throws AuthenticationApiException if the call is unsuccessful.
     */
    public void authorize(Map<String, String> queryParams, String authorization) throws AuthenticationApiException {
        HttpUrl.Builder httpBuilder = HttpUrl.parse(this.client.getBasePath() + "/oauth/authorize").newBuilder();
        if (queryParams != null) {
            for (Map.Entry<String, String> param : queryParams.entrySet()) {
                httpBuilder.addQueryParameter(param.getKey(), param.getValue());
            }
        }
        Headers.Builder headerBuilder = new Headers.Builder();
        if (authorization != null) {
            headerBuilder.add("Authorization", authorization);
        }
        Request request = new Request.Builder()
                .url(httpBuilder.build())
                .headers(headerBuilder.build())
                .get()
                .build();
        try {
            this.client.getHttpClient().newCall(request).execute();
        } catch (IOException e) {
            throw new AuthenticationApiException("Authorization error", e);
        }
    }
}
