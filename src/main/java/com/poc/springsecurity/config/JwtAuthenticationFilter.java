package com.poc.springsecurity.config;

import com.poc.springsecurity.service.JwtService;
import com.poc.springsecurity.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//class responsible for filtering each HTTP request and validating JWT tokens to manage user auth
//this class is a custom filter to intercept HTTP request and perform JWT-based auth before request processed further. Needs to be
//explicitly added to Spring Security filter chain
@Component
@RequiredArgsConstructor
//OncePerRequestFilter ensures filter executed only once per request
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    //service for handling JWT-related operations eg. token validation, extracting username from token
    private final JwtService jwtService;
    //service for loading user details from DB/another user store
    private final UserService userService;

    //core method for filter that processes each request. Params are HTTP request, HTTP response, and filterchain to pass request to next filter
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWithIgnoreCase(authHeader, "Bearer ")) {
            //if header is empty or does not start with "Bearer ", continue with next filter in the chain and return immediately
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserName(jwt);

        //check extracted email is not empty and there is already an authentication obj in the security context
        //aka User is already authenticated
        if (!StringUtils.isEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
            //load user details from userService using extracted email
            UserDetails userDetails = userService.userDetailsService().loadUserByUsername(userEmail);

            //Upon successful auth, user's details are encapsulated in a UsernamePasswordAuthenticationToken obj and stored in the SecurityContextHolder
            if (jwtService.isTokenValid(jwt, userDetails)) {
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                //UsernamePasswordAuthenticationToken is an Authentication object, created with UserDetails and set as authenticated
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //the token is set in SecurityContextHolder
                context.setAuthentication(authToken);
                SecurityContextHolder.setContext(context);
            }

        }
        //Continue with the filter chain
        filterChain.doFilter(request, response);
    }
}
