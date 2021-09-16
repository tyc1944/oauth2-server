package com.yunmo.auth.spring;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter @Setter
public class DomainUser extends User {
    private long userId;
    private long tenantId;
    private Long domain;

    public DomainUser(long userId,
                      long tenantId,
                      Long domain,
                      String username,
                      String password,
                      boolean enabled,
                      boolean accountNonExpired, boolean credentialsNonExpired,
                      boolean accountNonLocked,
                      Collection<? extends GrantedAuthority> authorities
                      ) {
        super(username, password, enabled,accountNonExpired,credentialsNonExpired, accountNonLocked,authorities);
        this.userId = userId;
        this.tenantId = tenantId;
        this.domain = domain;
    }
}
