package com.yunmo.auth.spring;

import com.yunmo.core.api.user.PersonnelService;
import com.yunmo.core.api.user.UserAccountService;
import com.yunmo.core.domain.user.AccountStatus;
import com.yunmo.core.domain.user.Personnel;
import com.yunmo.core.domain.user.UserAccount;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserPrincipalServiceImpl implements UserPrincipalService {

    public static final String DOMAIN_PARAMETER = "domain";

    @Autowired
    UserAccountService userAccountService;

    @Autowired
    PersonnelService personnelService;

    @Override
    public DomainUser loadUserByUsername(String username) {
        UserAccount userAccount = userAccountService.findByUsernameOrPhone(username);
        if (userAccount == null) {
            throw new UsernameNotFoundException(username);
        }

        var authorities = Optional.ofNullable(userAccount.getAuthorities()).map(a -> a.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList()))
                .orElse(new ArrayList<>());

        Long userId = userAccount.getTenantId();
        Long tenantId = userAccount.getTenantId();
        Long domain = null;
        String password = "{bcrypt}" + userAccount.getPassword();

//        Map<String, Object> parameters = (Map<String, Object>) (SecurityContextHolder.getContext().getAuthentication()).getDetails();

//        if (parameters.containsKey(DOMAIN_PARAMETER)) {
//            long domainId = Long.parseLong(parameters.get(DOMAIN_PARAMETER).toString());
//            Personnel personnel = personnelService.findByEnterpriseIdAndUserId(domainId, userAccount.getTenantId());
//            if (personnel == null) {
//                throw new UsernameNotFoundException(username);
//            }
//            authorities.add(new SimpleGrantedAuthority("ROLE_" + personnel.getRole()));
//
//            tenantId = personnel.getTenantId();
//            domain = personnel.getEnterpriseId();
//        }



        authorities.add(new SimpleGrantedAuthority("USER"));

        return new DomainUser(userId, tenantId, domain,
                userAccount.getAccountName(), password,
                userAccount.getStatus() == AccountStatus.NORMAL,
                true, true, userAccount.getStatus() != AccountStatus.LOCKED,
                authorities);
    }

}
