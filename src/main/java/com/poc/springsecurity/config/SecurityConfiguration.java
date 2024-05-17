package com.poc.springsecurity.config;

import com.poc.springsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//@Configuration is an annotation used to indicate that a class contains @Bean. This is a more centralized approach
// to consolidate beans than have them across multiple classes
@Configuration
//Allows customization of security in app
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserService userService;

    @Bean
    //securityFilterChain() called by Spring Framework during app startup. SpringBoot automatically applies the security configs defined
    //in the method if it detects @Configuration & @Bean of SecurityFilterChain
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                //any request matching "/api..." are all permitted without auth, but all other requests require auth
                .authorizeHttpRequests(request -> request.requestMatchers("/api/v1/auth/**").permitAll()
                        .anyRequest().authenticated())
                //configures server session management NOT to store session data, each request must be authenticated independently
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //sets custom AuthenticationProvider
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    //Custom AuthenticationProvider done here to customize auth process beyond default behaviour. Eg. custom password encoding using BCrypt
    public AuthenticationProvider authenticationProvider() {
        //Creates an instance of DaoAuthenticationProvider, which retrieves user details from a UserDetailsService.
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        //sets the UserDetailsService that this AuthProvider will use to load user details
        authProvider.setUserDetailsService(userService.userDetailsService());
        //sets the PasswordEncoder that this AuthProvider will use to encode passwords
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    //AuthenticationManager is a core Spring Security component to handle auth requests, delegates auth process to AuthenticationProviders
    //Central point to manage auth process
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        //AuthenticationConfiguration helps configure & expose AuthenticationManager @Bean
        //retrieves and returns the AuthenticationManager from AuthenticationConfiguration
        return config.getAuthenticationManager();
    }

}
