package gergaud.oidc.testclient.service;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * An in-memory session manager (do not use with a load balancer without sticky session).
 */
@Component
public class InMemorySessionManager {

    private final Map<String, JWT> iDTokenByUserID;
    private final Map<String, AccessToken> accessTokenByUserID;
    private final Map<String, RefreshToken> refreshTokenByUserID;

    InMemorySessionManager(){
        iDTokenByUserID = new HashMap<>();
        accessTokenByUserID = new HashMap<>();
        refreshTokenByUserID = new HashMap<>();
    }

    /**
     * Add a user from it token and returns the user's identifier. The user's identifier is taken from the ID token's
     * subject claim.
     * @param idToken The user's ID token.
     * @param accessToken The user's access token.
     * @param refreshToken The user's refresh token.
     * @returnThe user's identifier.
     * @throws ParseException if the ID Token could not be parsed.
     */
    public String addUser(JWT idToken, AccessToken accessToken, RefreshToken refreshToken) throws ParseException {
        String userID = idToken.getJWTClaimsSet().getSubject();
        iDTokenByUserID.put(userID, idToken);
        accessTokenByUserID.put(userID, accessToken);
        refreshTokenByUserID.put(userID, refreshToken);
        return userID;
    }

    public JWT getUserIDToken(String userID) {
        return iDTokenByUserID.get(userID);
    }

    public AccessToken getUserAccessToken(String userID) {
        return accessTokenByUserID.get(userID);
    }

    public RefreshToken getUserRefreshToken(String userID) {
        return refreshTokenByUserID.get(userID);
    }

    public void removeUser(String userID) {
        iDTokenByUserID.remove(userID);
        accessTokenByUserID.remove(userID);
        refreshTokenByUserID.remove(userID);
    }
}
