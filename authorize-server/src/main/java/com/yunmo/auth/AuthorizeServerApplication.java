package com.yunmo.auth;

import com.yunmo.boot.data.DataConfiguration;
import com.yunmo.boot.oauth2.resource.ResourceServerAutoConfig;
import com.yunmo.boot.web.security.SecurityAutoConfiguration;
import com.yunmo.core.UserGrpcConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.zalando.problem.spring.web.autoconfigure.security.ProblemSecurityAutoConfiguration;

@SpringBootApplication(exclude = {ProblemSecurityAutoConfiguration.class, DataConfiguration.class, SecurityAutoConfiguration.class, ResourceServerAutoConfig.class})
@Import(UserGrpcConfig.class)
public class AuthorizeServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizeServerApplication.class, args);
    }

}
