package com.yunmo.auth.spring.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    public static final String DOMAIN_DELIMITER  = "/";

    public static final String SELECT_USER_ACCOUNT_SQL_BY_ACCOUNT_NAME = "SELECT  id, account_name, enabled, password FROM user_account as ua where ua.account_name = ?";

    public static final String SELECT_USER_ACCOUNT_SQL_BY_STAFF_ID = "SELECT  id, account_name, enabled, password FROM user_account as ua where ua.staff_id = ?";

    public static final String SELECT_STAFF_BY_PHONE = "SELECT  id  FROM staff  where phone = ?";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public Staff getStaffId(String phone) {
        try {
            return jdbcTemplate.queryForObject(SELECT_STAFF_BY_PHONE, new BeanPropertyRowMapper<Staff>(Staff.class), phone);
        } catch (EmptyResultDataAccessException e) {
            return null;
        } catch (IncorrectResultSizeDataAccessException e) {
            throw new IncorrectResultSizeDataAccessException("员工数据存在多条对应记录",1);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount userAccount = null;
        try {
            userAccount = jdbcTemplate.queryForObject(SELECT_USER_ACCOUNT_SQL_BY_ACCOUNT_NAME, new BeanPropertyRowMapper<UserAccount>(UserAccount.class),username);
        } catch (EmptyResultDataAccessException e) {
        }

        if (userAccount == null) {
           try {
               Staff staff = getStaffId(username);
               if (staff == null) {
                   throw new UsernameNotFoundException("用户名不存在");
               }
               try {
                   userAccount = jdbcTemplate.queryForObject(SELECT_USER_ACCOUNT_SQL_BY_STAFF_ID, new BeanPropertyRowMapper<UserAccount>(UserAccount.class), staff.getId());
               } catch (IncorrectResultSizeDataAccessException e) {
                   throw new IncorrectResultSizeDataAccessException("账号数据存在多条对应员工编号",1);
               }
           } catch (EmptyResultDataAccessException e) {
               throw new UsernameNotFoundException("用户名不存在");
           }
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

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    private static class Staff{
        private Long id;
    }
}
