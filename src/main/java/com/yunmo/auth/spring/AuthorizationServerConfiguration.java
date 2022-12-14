package com.yunmo.auth.spring;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.yunmo.auth.util.privateKeyUtil;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2ConfigurationUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

import static com.yunmo.auth.util.PublicKeyUtil.readPublicKey;

@Configuration
public class AuthorizationServerConfiguration extends WebSecurityConfigurerAdapter {
    @Value("${jwt.token.verification-key}")
    private String verificationKey;
    @Value("${jwt.token.signing-key}")
    private String signingKey;

    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();
        authorizationServerConfigurer.tokenEndpoint(configurer -> {
                    configurer
                            .accessTokenRequestConverter(new DelegatingAuthenticationConverter(Arrays.asList(
                                    new OAuth2AuthorizationCodeAuthenticationConverter(),
                                    new OAuth2RefreshTokenAuthenticationConverter(),
                                    new OAuth2ClientCredentialsAuthenticationConverter(),
                                    new OAuth2PasswordAuthenticationConverter())));
                }
        );

        http.authenticationProvider(OAuth2ConfigurationUtils.passwordAuthenticationProvider(http, authenticationManager()));
        http.requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);
        http.sessionManagement().disable();

    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer("http://auth-server:9000").build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("dcs")
                .clientSecret("$2a$10$wF9v/0wVRhOYp6h42jV9YehfzoUzGDUF0oMrEKV02LCHcB1xyeczC")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .tokenSettings(getTokenSettings())
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/articles-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope("ALL")
                .scope("A")
                .scope("B")
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public TokenSettings getTokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofDays(365))
                .build();
    }

    @SneakyThrows
    public RSAKey getRSAKey() {
        return new RSAKey.Builder(readPublicKey(verificationKey))
                .privateKey(privateKeyUtil.loadKey(signingKey))
                .keyID("954fdb04-ac97-42e0-95db-3f44aa667bf1")
                .build();

    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = getRSAKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

}
