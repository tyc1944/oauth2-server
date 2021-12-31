package com.yunmo.auth.spring.user;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class TenantTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {
        context.getClaims().claims(claims -> {
            var principal = (DomainUser) context.getPrincipal().getPrincipal();
            String sub = principal.getUsername();
            String scope = principal.getAuthorities().stream()
                    .map(a->a.getAuthority())
                    .filter(a->context.getAuthorizedScopes().contains(a))
                    .collect(Collectors.joining(" "));

            if(principal.getDomain() != null) {
                claims.put(DomainUser.DOMAIN_NAME, principal.getDomain());
            }
            claims.put(JwtClaimNames.SUB, sub);
            claims.put(OAuth2ParameterNames.SCOPE, scope);

            claims.remove(JwtClaimNames.AUD);
            claims.remove(JwtClaimNames.NBF);
            claims.remove(JwtClaimNames.ISS);
            claims.remove(JwtClaimNames.IAT);

            claims.put(JwtClaimNames.JTI, UUID.randomUUID());
        });
    }
}
