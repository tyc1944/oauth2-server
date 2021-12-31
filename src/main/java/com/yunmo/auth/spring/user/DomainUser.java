package com.yunmo.auth.spring.user;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter @Setter
public class DomainUser extends User {
    public static final String DOMAIN_NAME = "domain";
    private long id;
    private Long domain;

    public DomainUser(long id,
                      Long domain,
                      String username,
                      String password,
                      boolean enabled,
                      boolean accountNonExpired, boolean credentialsNonExpired,
                      boolean accountNonLocked,
                      Collection<? extends GrantedAuthority> authorities
                      ) {
        super(username, password, enabled,accountNonExpired,credentialsNonExpired, accountNonLocked,authorities);
        this.id = id;
        this.domain = domain;
    }
}
