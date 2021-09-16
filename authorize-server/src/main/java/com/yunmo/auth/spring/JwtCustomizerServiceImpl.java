package com.yunmo.auth.spring;

import com.sun.security.auth.UserPrincipal;
import com.yunmo.auth.configuration.expand.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtCustomizerServiceImpl implements JwtCustomizer {
    @Override
    public void customizeToken(JwtEncodingContext context) {

        AbstractAuthenticationToken token = null;

        Authentication authenticataion = SecurityContextHolder.getContext().getAuthentication();

        if (authenticataion instanceof OAuth2ClientAuthenticationToken) {
            token = (OAuth2ClientAuthenticationToken) authenticataion;
        }

        if (token != null) {

            if (token.isAuthenticated() && OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication usernamePasswordAuthentication = null;
                AuthorizationGrantType authorizationGrantType = context.getAuthorizationGrantType();
                if (authorizationGrantType == AuthorizationGrantType.AUTHORIZATION_CODE) {
                    usernamePasswordAuthentication = context.getPrincipal();
                }

                if (authorizationGrantType == AuthorizationGrantType.PASSWORD) {
                    usernamePasswordAuthentication = context.get(OAuth2ResourceOwnerPasswordAuthenticationProvider.USERNAME_PASSWORD_AUTHENTICATION_KEY);
                }

                if (usernamePasswordAuthentication != null && usernamePasswordAuthentication instanceof UsernamePasswordAuthenticationToken) {
                    DomainUser principal = (DomainUser) usernamePasswordAuthentication.getPrincipal();
                    Long userId = principal.getUserId();
                    Set<String> authorities = principal.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toSet());

                    JwtClaimsSet.Builder jwtClaimSetBuilder = context.getClaims();
                    jwtClaimSetBuilder.claim(OAuth2ParameterNames.SCOPE, authorities);
                    jwtClaimSetBuilder.claim("userId", userId);
                }
            }
        }

    }
}
