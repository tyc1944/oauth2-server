package org.springframework.security.oauth2.server.authorization.web.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class OAuth2PasswordAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {
        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        String username = takeRequired(parameters, OAuth2ParameterNames.USERNAME);
        String password = takeRequired(parameters, OAuth2ParameterNames.PASSWORD);

        // scope (OPTIONAL)
        Set<String> requestedScopes = takeOptional(parameters, OAuth2ParameterNames.SCOPE)
                .map(scope->new HashSet<>(
                        Arrays.asList(StringUtils.delimitedListToStringArray(scope, " "))))
                .orElse(null);

        Map<String, Object> additionalParameters = new HashMap<>(parameters.toSingleValueMap());

        return new OAuth2PasswordAuthenticationToken(clientPrincipal, additionalParameters, requestedScopes,
                username, password);
    }

    private String takeRequired(MultiValueMap<String, String> parameters, String name) {
        return Optional.ofNullable(parameters.remove(name)).flatMap(v->{
            if(v.size() == 1 && StringUtils.hasText(v.get(0))) {
                return Optional.of(v.get(0));
            }
            return Optional.empty();
        }).orElseThrow(()->
                error(OAuth2ErrorCodes.INVALID_REQUEST, name,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI));
    }

    private Optional<String> takeOptional(MultiValueMap<String, String> parameters, String name) {
        return Optional.ofNullable(parameters.remove(name)).flatMap(v->{
            if(v.size() == 1 && StringUtils.hasText(v.get(0))) {
                return Optional.of(v.get(0));
            }
            throw error(OAuth2ErrorCodes.INVALID_REQUEST,name,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        });
    }

    private OAuth2AuthenticationException error(String errorCode, String parameterName, String errorUri) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        return new OAuth2AuthenticationException(error);
    }
}
