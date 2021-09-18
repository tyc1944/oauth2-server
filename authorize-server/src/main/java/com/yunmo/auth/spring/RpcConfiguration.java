package com.yunmo.auth.spring;

import com.yunmo.boot.genrpc.FixedTokenJwtClientInterceptor;
import io.grpc.ClientInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RpcConfiguration {
    @Bean
    public ClientInterceptor fixedTokenJwtClientInterceptor() {
        return new FixedTokenJwtClientInterceptor("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwIn0.dXAhLAn5zIFoXL6LP9l-MPWOrgBiTyejuulaxrKZmF_5DnX1mzLNKjd4mUAFvPOiSqd0UHZqEvEP8lXYvuXTPirsL2tIsA4ZwrVqoGtL4ghnC9NPzny_YVWNPHm8t-_SsUBgngaFukPr5Cy2siQZnBXfW-gH0reNqNbm8Yoadio6uAiisuhJxzTQuEEfgeYUD0Xwm1QUgRNSSKUQSfXDOvE5Lw-gTQxvpUXdlhRSZBiKDcKG5pzskkECy4B8LQY-bYUu882M-Y3wBjWrWUCzEZCd1VltPgBUNoaHVTPgSa6D02e9Kbh19kmE81Z4h7NwlRqVl7JykBl2SgybIYrbFQ");
    }
}
