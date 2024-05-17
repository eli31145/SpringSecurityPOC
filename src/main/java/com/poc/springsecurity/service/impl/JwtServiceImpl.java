package com.poc.springsecurity.service.impl;

import com.poc.springsecurity.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtServiceImpl implements JwtService {
    //injects a signing key from app configuration using Dependency Injection
    @Value("${token.signing.key}")
    private String jwtSigningKey;

    @Override
    //extracts username(subject) from JWT
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256).compact();
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = userDetails.getUsername();
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //generic method to extract specific claim from JWT
    //claimsResolvers is a function to resolve a specific claim from claims
    private <T>T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        //uses function from claimsResolvers to extract specific claim
        return claimsResolvers.apply(claims);
    }

    //Parses JWT to extract all claims, returns all claims contained in the JWT
    private Claims extractAllClaims(String token) {
        //Uses JWT parser to parse JWT, sets signing key, builds and gets body to parse JWT and get claims
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                //note previous error using function parseClaimsJwt(token) which throws error as it is for parsing unsigned JWTs
                .build().parseClaimsJws(token).getBody();
    }

    //Converts the base64-encoded string (jwtSigningKey) into a byte array, which is then used to create an HMAC SHA key
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSigningKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
