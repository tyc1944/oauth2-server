package com.yunmo.auth.spring.user;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
@Service
public class UserDetailServiceImpl implements UserDetailsService {
    public static final String DOMAIN_DELIMITER  = "/";

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String[] segments = username.split(DOMAIN_DELIMITER); //支持username中加入domain

        if(segments.length > 1) {
            String domain = segments[0];
            username = segments[1];
            return new DomainUser(2l, 1l, username, "{noop}123456",
                    true, true, true,true,
                    Arrays.asList(new SimpleGrantedAuthority("A"), new SimpleGrantedAuthority("B")));
        }

        return new DomainUser(1l,null, username, "{noop}123456",
                true, true, true,true,
                Arrays.asList(new SimpleGrantedAuthority("A")));
    }
}
