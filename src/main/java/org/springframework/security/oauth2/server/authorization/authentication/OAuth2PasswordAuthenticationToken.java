package org.springframework.security.oauth2.server.authorization.authentication;

import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Map;
import java.util.Set;

@Getter
public class OAuth2PasswordAuthenticationToken extends AbstractOAuth2ScopedAuthenticationToken {
    private final UsernamePasswordAuthenticationToken authenticationToken;

    public OAuth2PasswordAuthenticationToken(Authentication clientPrincipal, Map<String, Object> additionalParameters,
                                             Set<String> scopes, String username, String password) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters, scopes);
        this.authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
    }
}
