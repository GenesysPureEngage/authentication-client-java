# Authentication Client Library

The Authentication Client Library is a Java wrapper for the [Authentication API](https://developer.genhtcc.com/api/reference/authentication/) that makes it easier to code against the API. The library provides much of the supporting code needed to make HTTP requests and process HTTP responses.

The library is hosted on [GitHub](https://github.com/GenesysPureEngage/authentication-client-java) and Genesys welcomes pull requests for corrections.

## Install

Genesys recommends that you install the Authentication Client Library JAR file with [Gradle](https://gradle.org) . You should use the latest version available at https://maven2repo.com/com.genesys/authorization.

Add the following line to the **dependencies** block in your **build.gradle** file:

``` gradle
compile 'com.genesys:authorization:<latest_version>'
```

## Related Links

* Learn more about the [Authentication API](https://developer.genhtcc.com/api/reference/authentication/).
* Learn more about the [Authentication Client Library](https://developer.genhtcc.com/api/client-libraries/authentication/java/AuthenticationApi/index.html).

## Classes

The Authentication Client Library includes one main class, [AuthenticationApi](https://developer.genhtcc.com/api/client-libraries/authentication/java/AuthenticationApi/index.html). This class contains all the resources and events that are part of the Authentication API, along with all the methods you need to access the API functionality.

## Examples

Here's an example of how you can use the Authentication Client Library to authenticate using the [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3) type.

``` java
import com.genesys.internal.authorization.api.AuthenticationApi;
import com.genesys.internal.authorization.model.DefaultOAuth2AccessToken;
import com.genesys.internal.common.ApiClient;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        String apiKey = "<apiKey>";
        String apiUrl = "<apiUrl>";

        String authUrl = String.format("%s/auth/v3", apiUrl);
        ApiClient authClient = new ApiClient();
        authClient.setBasePath(authUrl);
        authClient.addDefaultHeader("x-api-key", apiKey);
        authClient.getHttpClient().setFollowRedirects(false);

        AuthenticationApi authApi = new AuthenticationApi(authClient);

        String agentUsername = "<agentUsername>";
        String agentPassword = "<agentPassword>";
        String clientId = "<clientId>";
        String clientSecret = "<clientSecret>";

        String authorization = "Basic " + new String(Base64.getEncoder().encode(String.format("%s:%s", clientId, clientSecret).getBytes()));

        // Get OAuth2.0 token
        DefaultOAuth2AccessToken resp = authApi.retrieveToken("password", authorization, "application/json", "*", clientId, agentUsername, agentPassword);
   }
}
```

For usage examples for each method available in the library, see the documentation for the [AuthenticationAPi](https://developer.genhtcc.com/api/client-libraries/authentication/java/AuthenticationApi/index.html) class.