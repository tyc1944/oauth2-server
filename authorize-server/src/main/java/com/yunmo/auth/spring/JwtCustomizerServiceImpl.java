package com.yunmo.auth.spring;

import com.sun.security.auth.UserPrincipal;
import com.yunmo.auth.configuration.expand.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import com.yunmo.domain.common.Tenant;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
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

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof OAuth2ClientAuthenticationToken) {
            token = (OAuth2ClientAuthenticationToken) authentication;
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

                if (usernamePasswordAuthentication instanceof UsernamePasswordAuthenticationToken) {
                    DomainUser domainUser = (DomainUser) usernamePasswordAuthentication.getPrincipal();
                    Set<String> authorities = domainUser.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toSet());
                    //自定义payload
                    JwtClaimsSet.Builder jwtClaimSetBuilder = context.getClaims();
                    jwtClaimSetBuilder.claim(OAuth2ParameterNames.SCOPE, authorities);
                    jwtClaimSetBuilder.subject(String.valueOf(domainUser.getTenantId()));
                    if (domainUser.getDomain() != null) {
                        jwtClaimSetBuilder.claim(Tenant.CLAIM_DOMAIN, domainUser.getDomain());
                    }
                    if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
                        jwtClaimSetBuilder.claim("authorities", AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
                    }
                }
            }
        }

    }
}
