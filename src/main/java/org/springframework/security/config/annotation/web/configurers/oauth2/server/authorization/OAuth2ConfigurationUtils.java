package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;

public class OAuth2ConfigurationUtils {
    @SneakyThrows
    public static OAuth2PasswordAuthenticationProvider passwordAuthenticationProvider(HttpSecurity builder,
                                                                                     AuthenticationManager authenticationManager)  {
        JwtEncoder jwtEncoder = OAuth2ConfigurerUtils.getJwtEncoder(builder);
        OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = OAuth2ConfigurerUtils.getJwtCustomizer(builder);

        ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
        var provider = new OAuth2PasswordAuthenticationProvider(authenticationManager,
                OAuth2ConfigurerUtils.getAuthorizationService(builder), jwtEncoder, providerSettings);

        if(jwtCustomizer != null) {
            provider.setJwtCustomizer(jwtCustomizer);
        }
        return provider;
    }
}
