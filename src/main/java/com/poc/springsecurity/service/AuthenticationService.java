package com.poc.springsecurity.service;

import com.poc.springsecurity.dao.request.SignUpRequest;
import com.poc.springsecurity.dao.request.SigninRequest;
import com.poc.springsecurity.dao.response.JwtAuthenticationResponse;

public interface AuthenticationService {
    JwtAuthenticationResponse signup(SignUpRequest request);
    JwtAuthenticationResponse signin(SigninRequest request);
}
