package com.genesys.authentication;

public class AuthenticationApiException extends Exception {

    public AuthenticationApiException(String msg, Exception cause) {
        super(msg, cause);
    }
}
