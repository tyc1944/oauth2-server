package com.yunmo.auth.spring;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.validation.annotation.Validated;

@Validated
public interface UserPrincipalService extends UserDetailsService {

	@Override
    DomainUser loadUserByUsername(String username);
	
}
