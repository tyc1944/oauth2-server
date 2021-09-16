package com.yunmo.auth.spring;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import java.util.HashSet;

@Service
public class UserPrincipalServiceImpl implements UserPrincipalService {

    @Override
    public DomainUser loadUserByUsername(String username) {
        return new DomainUser(1, 1, 1L, "admin", "{bcrypt}$2a$10$kUupVuJ9I0VRDmLW0bmDXuLPDZdUCz2VG5BLHxSeWDFdqKcYlu9ey", true, true, true, true, new HashSet<>());
    }


    public static void main(String[] args) {
        System.out.println(BCrypt.hashpw("admin", BCrypt.gensalt()));
    }

}
