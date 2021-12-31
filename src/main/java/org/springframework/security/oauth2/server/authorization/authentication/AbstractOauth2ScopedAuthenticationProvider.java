package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

public abstract class AbstractOauth2ScopedAuthenticationProvider<T extends AbstractOAuth2ScopedAuthenticationToken>
        implements AuthenticationProvider {
    protected static final StringKeyGenerator DEFAULT_REFRESH_TOKEN_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
    protected Supplier<String> refreshTokenGenerator = DEFAULT_REFRESH_TOKEN_GENERATOR::generateKey;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        T authenticationToken = (T) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(authenticationToken);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Set<String> authorizedScopes = new LinkedHashSet<>(registeredClient.getScopes());
        if (!CollectionUtils.isEmpty(authenticationToken.getScopes())) {
            Set<String> unauthorizedScopes = authenticationToken.getScopes().stream()
                    .filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
                    .collect(Collectors.toSet());
            if (!CollectionUtils.isEmpty(unauthorizedScopes)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }

            authorizedScopes = new LinkedHashSet<>(authenticationToken.getScopes());
        }


        return authenticate(clientPrincipal, authenticationToken, authorizedScopes);
    }

    abstract Authentication authenticate(OAuth2ClientAuthenticationToken clientPrincipal, T authentication,
                                         Set<String> authorizedScopes) throws AuthenticationException;


    protected OAuth2RefreshToken refreshToken(OAuth2ClientAuthenticationToken clientPrincipal) {
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getRefreshTokenTimeToLive());

            return new OAuth2RefreshToken(this.refreshTokenGenerator.get(), issuedAt, expiresAt);
        }
        return null;
    }
}
