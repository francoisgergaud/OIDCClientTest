package gergaud.oidc.testclient.service;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import gergaud.oidc.testclient.controller.OIDCAuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;

@Component
public class OIDCService {

    private final OIDCProviderMetadata providerMetadata;
    private final ClientID clientID;
    private final Secret clientSecret;
    private JWKSet jwkSet;

    /**
     * Initialize le communication with the OIDC server (OP) by fetching its "/.well-known/openid-configuration" configuration.
     * This controller will fail to initialize if any communication problems happens.
     *
     * @param oidcProviderUrl The OIDC provider's openid-configuration URL.
     * @param clientId        The client's identifier configured in the OIDC provider.
     * @param clientSecret    The client's secret configured in the OIDC provider.
     * @throws URISyntaxException       if the CLIENT_REDIRECT_URI is not a valid URL.
     * @throws MalformedURLException    if the .well-known/openid-configuration provided by the OIDC server (OP) is not a valid URL.
     * @throws IOException              if the .well-known/openid-configuration URL is not reachable or if the JWE configuration is
     *                                  not reachable.
     * @throws ParseException           if the .well-known/openid-configuration could not be parsed.
     * @throws java.text.ParseException if the jwkSet (keys used for token signature) could not be parsed.
     */
    @Autowired
    OIDCService(
            @Value("${oidcProvider.openid-configuration.url}") String oidcProviderUrl,
            @Value("${oidc.clientId}") String clientId,
            @Value("${oidc.clientSecret}") String clientSecret
    ) throws URISyntaxException, IOException, ParseException, java.text.ParseException {
        this.clientID = new ClientID(clientId);
        this.clientSecret = new Secret(clientSecret);
        URL providerConfigurationURL = new URL(oidcProviderUrl);
        InputStream stream = providerConfigurationURL.openStream();
        Scanner scanner = new Scanner(stream);
        String providerMetadataRaw = scanner.useDelimiter("\\A").next();
        this.providerMetadata = OIDCProviderMetadata.parse(providerMetadataRaw);
        //fetches the JWK
        refreshKeyList();
    }

    /**
     * Fetches the JWK configuration from the OIDC server.
     *
     * @throws ParseException if the JWK configuration is not parsable.
     */
    private void refreshKeyList() throws IOException, java.text.ParseException {
        this.jwkSet = JWKSet.load(this.providerMetadata.getJWKSetURI().toURL());
    }

    /**
     * Get the OIDC server (OP) authentication's URI with the required parameter for the authentication process.
     *
     * @param scope The scope parameter to set for the authentication.
     * @param state The state parameter to set for the authentication.
     * @param nonce The nonce parameter to set for the authentication.
     * @param exchangeTokenURI The URI to redirect the user to once the authentication is done by the OIDC server (OP).
     * @return The authentication URI.
     */
    public URI getAuthenticationURI(Scope scope, State state, Nonce nonce, URI exchangeTokenURI) {
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                providerMetadata.getAuthorizationEndpointURI(),
                new ResponseType(ResponseType.Value.CODE),
                scope, this.clientID, exchangeTokenURI, state, nonce);
        return authenticationRequest.toURI();
    }

    /**
     * Process the request to exchange an authentication-code. IT first validates that the
     * state parameter's value is as expected and extract tha authentication-code from the URL.
     *
     * @param request The request from the client.
     * @param state   The state value which should be set in the request.
     * @return The authentication code from the request
     * @throws ParseException              if the request could not be parsed correctly, that is, if this is not a authentication-code
     *                                     to token exchange request.
     * @throws OIDCAuthenticationException if error is present in the request or the State vvalidation fails.
     */
    public AuthorizationCode validateStateAndGetAuthorizationCodeFromRequest(URI request, State state) throws ParseException, OIDCAuthenticationException {
        AuthenticationResponse authResp = AuthenticationResponseParser.parse(request);
        if (authResp instanceof AuthenticationErrorResponse) {
            ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
            throw new OIDCAuthenticationException(error.getDescription());
        }

        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;
        if (!successResponse.getState().equals(state)) {
            throw new OIDCAuthenticationException("state verification failed.");
        }

        return successResponse.getAuthorizationCode();
    }

    /**
     * Exchange an authorization-code for an access-token and an ID Token.
     *
     * @param authorizationCode The authorization to exchange for the tokens.
     * @return The OIDC tokens, containing the access-token, the ID Token and the refresh-token.
     * @throws IOException                 if the communication with OIDC server (OP) failed.
     * @throws ParseException              if the response from the OIDC server could not be parsed.
     * @throws OIDCAuthenticationException if the OIDC server's response is an error.
     */
    public OIDCTokens getTokensFromAuthenticationCode(AuthorizationCode authorizationCode, URI redirectURI) throws IOException, ParseException, OIDCAuthenticationException {
        TokenRequest tokenRequest = new TokenRequest(
                providerMetadata.getTokenEndpointURI(),
                new ClientSecretBasic(this.clientID, this.clientSecret),
                new AuthorizationCodeGrant(authorizationCode, redirectURI));
        HTTPResponse httpTokenResponse = tokenRequest.toHTTPRequest().send();
        TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpTokenResponse);
        if (tokenResponse instanceof TokenErrorResponse) {
            ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
            throw new OIDCAuthenticationException(error.getDescription());
        }
        AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;
        return accessTokenResponse.getTokens().toOIDCTokens();
    }

    /**
     * Fetches the user-information from the OIDC Server (OP) from an access-token.
     *
     * @param accessToken The access token.
     * @return The user-information claims.
     * @throws IOException                 if the communication with OIDC server (OP) failed.
     * @throws ParseException              if the response from the OIDC server could not be parsed.
     * @throws OIDCAuthenticationException if the OIDC server's response is an error.
     */
    public UserInfo getUserInfoFromAccessTokens(AccessToken accessToken) throws IOException, ParseException, OIDCAuthenticationException {
        UserInfoRequest userInfoRequest = new UserInfoRequest(providerMetadata.getUserInfoEndpointURI(), accessToken);
        HTTPResponse userInfoHTTPResponse = userInfoRequest.toHTTPRequest().send();
        UserInfoResponse userInfoResponse = UserInfoResponse.parse(userInfoHTTPResponse);
        if (userInfoResponse instanceof UserInfoErrorResponse) {
            ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
            throw new OIDCAuthenticationException(error.getDescription());
        }
        UserInfoSuccessResponse successResponse = (UserInfoSuccessResponse) userInfoResponse;
        return successResponse.getUserInfo();
    }

    /**
     * Get the OIDC server (OP) session-logout's redirect-URL. This URL is the OIDC server's logout endpoint with some
     * specific parameters (one of them is the redirect-URL after logout).
     *
     * @param idToken     The user's ID Token to close the SSO session for.
     * @param redirectUri The redirect URI to which the user will be redirected.
     * @return The URI of the OIDC server (OP) session-logout.
     */
    public URI logout(JWT idToken, URI redirectUri) {
        URI endSessionEndpoint = providerMetadata.getEndSessionEndpointURI();
        LogoutRequest logoutRequest = new LogoutRequest(endSessionEndpoint, idToken, redirectUri, new State());
        return logoutRequest.toURI();
    }

    /**
     * Verifies the ID token's signature with the public-keys provided by the OIDC server.
     *
     * @param idToken The ID token to verify.
     * @return true if the signature of the JWT could be verified successfully, false otherwise.
     * @throws OIDCAuthenticationException if any ID Token validation happens.
     * @throws ParseException              if the key from OIDC OP (in JSON format) could not be parsed.
     * @throws JOSEException               if the key from OIDC OP could not be set.
     */
    public boolean verifyJWT(JWT idToken) throws OIDCAuthenticationException, java.text.ParseException, JOSEException {
        String keyId = idToken.getHeader().toJSONObject().get("kid").toString();
        JWK jwk = this.jwkSet.getKeyByKeyId(keyId);
        if (jwk == null) {
            throw new OIDCAuthenticationException("invalid key in JWT header.");
        }
        if (!jwk.getKeyUse().equals(KeyUse.SIGNATURE)) {
            throw new OIDCAuthenticationException("invalid key use in JWT header.");
        }
        JWSVerifier verifier;
        Algorithm signatureAlg = jwk.getAlgorithm();
        if (JWSAlgorithm.Family.RSA.contains(signatureAlg)) {
            verifier = new RSASSAVerifier(jwk.toRSAKey());
        } else if (JWSAlgorithm.Family.HMAC_SHA.contains(signatureAlg)) {
            verifier = new MACVerifier(jwk.toOctetSequenceKey());
        } else if (JWSAlgorithm.Family.ED.contains(signatureAlg)) {
            verifier = new Ed25519Verifier(jwk.toOctetKeyPair());
        } else if (JWSAlgorithm.Family.EC.contains(signatureAlg)) {
            verifier = new ECDSAVerifier(jwk.toECKey());
        } else {
            throw new OIDCAuthenticationException(signatureAlg + " signature algorithm is not managed.");
        }
        SignedJWT signedJWT = SignedJWT.parse(idToken.getParsedString());
        return signedJWT.verify(verifier);
    }
}
