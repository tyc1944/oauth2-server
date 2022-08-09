package com.yunmo.auth.spring.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    public static final String DOMAIN_DELIMITER = "/";

    public static final String SELECT_USER_ACCOUNT_SQL_BY_ACCOUNT_NAME = "SELECT  id, account_name,phone, enabled, password FROM user_account as ua where ua.account_name = ? ";
    public static final String SELECT_USER_ACCOUNT_SQL_BY_PHONE = "SELECT  id, account_name, phone,enabled, password FROM user_account as ua where ua.phone = ? ";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount userAccount = null;
        try {
            userAccount = jdbcTemplate.queryForObject(SELECT_USER_ACCOUNT_SQL_BY_ACCOUNT_NAME, new BeanPropertyRowMapper<UserAccount>(UserAccount.class), username);
        } catch (EmptyResultDataAccessException ignored) {
        }

        if (userAccount == null) {
            try {
                userAccount = jdbcTemplate.queryForObject(SELECT_USER_ACCOUNT_SQL_BY_PHONE, new BeanPropertyRowMapper<UserAccount>(UserAccount.class), username);
            } catch (EmptyResultDataAccessException e) {
                throw new UsernameNotFoundException("用户名不存在");
            } catch (IncorrectResultSizeDataAccessException e) {
                throw new IncorrectResultSizeDataAccessException("手机关联多个账号数据", 1);
            }
        }

        return new DomainUser(userAccount.getId(), null, username, userAccount.getPassword(),
                userAccount.isEnabled(), true, true, true,
                List.of());
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    private static class UserAccount {
        private Long id;
        private String phone;
        private String password;
        private String accountName;
        private boolean enabled;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    private static class Staff {
        private Long id;
    }
}
