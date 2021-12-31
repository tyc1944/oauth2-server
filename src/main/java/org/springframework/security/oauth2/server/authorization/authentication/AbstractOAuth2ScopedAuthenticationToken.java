package org.springframework.security.oauth2.server.authorization.authentication;

import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Map;
import java.util.Set;

@Getter
public abstract class AbstractOAuth2ScopedAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken{
    private final Set<String> scopes;


    protected AbstractOAuth2ScopedAuthenticationToken(AuthorizationGrantType authorizationGrantType,
                                                      Authentication clientPrincipal, Map<String, Object> additionalParameters,
                                                      Set<String> scopes) {
        super(authorizationGrantType, clientPrincipal, additionalParameters);
        this.scopes = scopes;
    }
}
