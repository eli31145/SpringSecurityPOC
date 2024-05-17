package com.poc.springsecurity.service;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService {
    //UserDetailsService is an interface that retrieves the user's authentication and auth info.
    //Contains only 1 function which can be implemented to supply user info to Spring Security API.
    UserDetailsService userDetailsService();
}
