package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.util.Assert;

import java.util.Set;

public  class OAuth2PasswordAuthenticationProvider extends AbstractOauth2ScopedAuthenticationProvider<OAuth2PasswordAuthenticationToken> {

    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    private final JwtEncoder jwtEncoder;
    private final ProviderSettings providerSettings;

    private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {
    };

    public OAuth2PasswordAuthenticationProvider(AuthenticationManager authenticationManager,
                                                OAuth2AuthorizationService authorizationService,
                                                JwtEncoder jwtEncoder,
                                                ProviderSettings providerSettings) {
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
        this.jwtEncoder = jwtEncoder;
        this.providerSettings = providerSettings;
    }


    @Override
    Authentication authenticate(OAuth2ClientAuthenticationToken clientPrincipal,
                                OAuth2PasswordAuthenticationToken passwordAuthentication,
                                Set<String> authorizedScopes) throws AuthenticationException {
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        Authentication usernamePasswordAuthentication = authenticationManager.authenticate(passwordAuthentication.getAuthenticationToken());


        String issuer = this.providerSettings != null ? this.providerSettings.getIssuer() : null;

        JoseHeader.Builder headersBuilder = JwtUtils.headers();
        JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
                registeredClient, issuer, usernamePasswordAuthentication.getName(), authorizedScopes);

        JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthentication)
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrant(passwordAuthentication)
                .build();

        this.jwtCustomizer.customize(context);

        JoseHeader headers = context.getHeaders().build();
        JwtClaimsSet claims = context.getClaims().build();
        Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
                jwtAccessToken.getExpiresAt(), authorizedScopes);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getName())
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .token(accessToken,
                        (metadata) ->
                                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims()))
                .attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes);


        OAuth2Authorization authorization = authorizationBuilder.build();

        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, usernamePasswordAuthentication, accessToken, refreshToken(clientPrincipal));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public final void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
        this.jwtCustomizer = jwtCustomizer;
    }
}
