package com.yunmo.auth.spring.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    public static final String DOMAIN_DELIMITER  = "/";

    public static final String SELECT_USER_ACCOUNT_SQL = "SELECT  id, account_name, enabled, password FROM user_account as ua where ua.account_name = ?";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount userAccount = null;
        try {
            userAccount = jdbcTemplate.queryForObject(SELECT_USER_ACCOUNT_SQL, new BeanPropertyRowMapper<UserAccount>(UserAccount.class),username);
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException("用户名不存在");
        }

        String[] segments = username.split(DOMAIN_DELIMITER); //支持username中加入domain
        if(segments.length > 1) {
            String domain = segments[0];
            username = segments[1];
            return new DomainUser(userAccount.getId(), Long.valueOf(domain), username,  userAccount.getPassword(),
                    userAccount.isEnabled(), true, true, true,
                    List.of());
        }

        return new DomainUser(userAccount.getId(),null, username, userAccount.getPassword(),
                userAccount.isEnabled(), true, true,true,
                List.of());
    }

    public static class CustomerRowMapper implements RowMapper<UserAccount> {

        @Override
        public UserAccount mapRow(ResultSet rs, int rowNum) throws SQLException {
            return UserAccount.builder()
                    .id(rs.getLong("id"))
                    .accountName(rs.getString("account_name"))
                    .enabled(rs.getBoolean("enabled"))
                    .password(rs.getString("password"))
                    .build();

        }
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    private static class UserAccount {
        private Long id;
        private String password;
        private String accountName;
        private boolean enabled;
    }
}
