package gergaud.oidc.testclient.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import gergaud.oidc.testclient.service.InMemorySessionManager;
import gergaud.oidc.testclient.service.OIDCService;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * This controller manages the OIDC authentication-code grant flow. There are 2 requests managed by this controller:
 * 1. requestAuthentication: The user triggers the authentication flow. This will redirect the user to the OIDC server.
 * 2. getTokenFromAuthenticationCode: After having validated the user's session or credentials,tThe OIDC server
 * redirected the user to this controller with the authentication-code. The authentication-code will be exchanged with
 * an ID Token (which can be used as a session ID later on) and an access token, which is stored on server side.
 * from https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/guides/java-cookbook-for-openid-connect-public-clients
 */
@Controller
public class OIDCController {

    private static final String AUTHENTICATION_CODE_EXCHANGE_URL_MAPPING = "/exchangeToken";
    private static final String USER_ID_COOKIE_NAME = "user-id";
    private static final String STATE_COOKIE_NAME = "state";

    private final URI authenticationCodeExchangeURL;
    private final URI applicationBaseURL;

    @Resource
    OIDCService oidcService;

    @Resource
    InMemorySessionManager sessionManager;

    /**
     * Initialize the controller and its components.
     * @param applicationBaseURL The OIDC redirect-URI. This is the application's URL and it must match with the Redirect URI
     *                        configured in the OIDC provider's client.
     */
    OIDCController(@Value("${application.baseURL}") URI applicationBaseURL) throws URISyntaxException {
        this.applicationBaseURL = applicationBaseURL;
        this.authenticationCodeExchangeURL = new URI(applicationBaseURL + AUTHENTICATION_CODE_EXCHANGE_URL_MAPPING);
    }

    /**
     * Triggers the authentication process by redirecting the user (RP) to the OIDC server (OP). It sets the request with
     * a random/unguessable "state" value which will be verified later on to ensure there is no CSRF.
     * @param response The servlet response used for redirect.
     * @throws IOException if the user could not be redirected to the OIDC server login/session page.
     */
    @GetMapping("/authenticate")
    public void requestAuthentication(HttpServletResponse response) throws IOException {
        // Generate random state string for pairing the response to the request
        State state = new State();
        // Generate nonce
        Nonce nonce = new Nonce();
        // Specify scope
        Scope scope = Scope.parse("openid");
        URI authenticationRequestURI = oidcService.getAuthenticationURI(scope, state, nonce, this.authenticationCodeExchangeURL);
        // Set the state cookie to get it back later for validation.
        // for a Cookie,  if the domain is not set, the browser will set it with the current one from the URL:
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
        Cookie stateCookie =new Cookie(STATE_COOKIE_NAME, state.getValue());
        stateCookie.setHttpOnly(true);
        stateCookie.setMaxAge(120);
        stateCookie.setSecure(true);
        response.addCookie(stateCookie);
        response.sendRedirect(authenticationRequestURI.toString());
    }

    /**
     * Receives the authentication-code provided by the OIDC server (OP) and get the tokens from it. It then stores the
     * access-token in memory and uses the ID token as a stateless session identifier. This is a (really) basic session-management
     * implementation.
     * In the end, it redirects the user to the "userinfo" controller.
     *
     * @param request  The redirect HTTP request to get the authentication code from.
     * @param response The HTTP servlet response use for redirection.
     * @return the view to be displayed.
     * @throws OIDCAuthenticationException if any authentication error happened.
     * @throws URISyntaxException          if the URL for this request has an invalid format (can it ever happen?).
     * @throws ParseException              if the URL for this request failed to be parsed to extract the authentication code.
     * @throws IOException                 if an error occurred while getting the tokens from the OIDC server (OP).
     * @throws JOSEException               if the ID token signature could not be validated.
     */
    @GetMapping(AUTHENTICATION_CODE_EXCHANGE_URL_MAPPING)
    public void getTokenFromAuthenticationCode(
            @CookieValue(name = STATE_COOKIE_NAME) String stateValue,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws OIDCAuthenticationException, URISyntaxException, ParseException, IOException, java.text.ParseException, JOSEException {
        String requestURI = request.getRequestURL().toString() + "?" + request.getQueryString();
        State state = new State(stateValue);
        AuthorizationCode authenticationCode = oidcService.validateStateAndGetAuthorizationCodeFromRequest(new URI(requestURI), state);
        OIDCTokens oidcTokens = oidcService.getTokensFromAuthenticationCode(authenticationCode, this.authenticationCodeExchangeURL);
        // verify the signature of the ID Token which is an JWT.
        oidcService.verifyJWT(oidcTokens.getIDToken());
        String userID = sessionManager.addUser(oidcTokens.getIDToken(), oidcTokens.getAccessToken(), oidcTokens.getRefreshToken());
        // set the userID as a cookie for session management. Anything else can be implemented here
        Cookie idTokenCookie =new Cookie(USER_ID_COOKIE_NAME, userID);
        idTokenCookie.setHttpOnly(true);
        idTokenCookie.setMaxAge(300);
        idTokenCookie.setSecure(true);
        response.addCookie(idTokenCookie);
        // remove the state cookie as state is validated
        Cookie stateCookie =new Cookie(STATE_COOKIE_NAME, null);
        stateCookie.setHttpOnly(true);
        stateCookie.setMaxAge(0);
        stateCookie.setSecure(true);
        response.addCookie(stateCookie);
        // redirect the user to the userInfo, which in turn triggers the userInfo method from this controller. Anything
        // else can be implemented here
        response.sendRedirect("userInfoView.html");
    }

    /**
     * Fetches the user-information. The user is identified by its session-identifier (the ID token here), in order to
     * fetch its access-token. The access-token is then used to call the user-info endpoint.
     *
     * @param userID The user identifier stored in the cookie.
     * @return the user's claims in JSON format.
     * @throws IOException                 if the request to the OIDC server's user-info failed.
     * @throws ParseException              if the response from  OIDC server's user-info endpoint could not be parsed.
     * @throws OIDCAuthenticationException if the response  OIDC server's from user-info endpoint is an error.
     */
    @GetMapping("/userInfo")
    @ResponseBody
    public JSONObject getUserInfoFromAccessTokens(@CookieValue(name = USER_ID_COOKIE_NAME) String userID) throws IOException, ParseException, OIDCAuthenticationException {
        AccessToken accessToken = sessionManager.getUserAccessToken(userID);
        UserInfo userInfo = oidcService.getUserInfoFromAccessTokens(accessToken);
        return userInfo.toJSONObject();
    }

    /**
     * Logout a user from the OIDC session.
     *
     * @param userID  The user's identifier.
     * @param response The HTTP response used for the redirect.
     * @throws IOException If the OIDC server (OP) could not be reached.
     * @throws java.text.ParseException If the ID Token could not be parsed.
     */
    @GetMapping("/logout")
    @ResponseBody
    public void logout(
            @CookieValue(name = USER_ID_COOKIE_NAME) String userID,
            HttpServletResponse response
    ) throws IOException {
        JWT idToken = sessionManager.getUserIDToken(userID);
        URI logoutURI = oidcService.logout(idToken, this.applicationBaseURL);
        sessionManager.removeUser(userID);
        Cookie idTokenCookie =new Cookie(USER_ID_COOKIE_NAME, null);
        idTokenCookie.setHttpOnly(true);
        idTokenCookie.setMaxAge(0);
        idTokenCookie.setSecure(true);
        response.addCookie(idTokenCookie);
        response.sendRedirect(logoutURI.toString());
    }
}
