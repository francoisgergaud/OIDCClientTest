package gergaud.oidc.testclient.controller;

/**
 * This exception is used to encapsulate any problem happening during the OIDC authentication process.
 */
public class OIDCAuthenticationException extends Exception{

    public OIDCAuthenticationException(String message){
        super(message);
    }
}
