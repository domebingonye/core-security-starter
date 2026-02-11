package com.sbsc.security.core_security_starter.util;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.function.Function;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtTokenUtil implements Serializable {

    public String getUsernameFromToken(String token, String jwtClientSecret) {
        return getClaimFromToken(token, Claims::getSubject, jwtClientSecret);
    }    //retrieve expiration date from jwt token

    public Date getExpirationDateFromToken(String token,  String jwtClientSecret) {
        return getClaimFromToken(token, Claims::getExpiration, jwtClientSecret);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver, String jwtClientSecret) {
        final Claims claims = getAllClaimsFromToken(token, jwtClientSecret);
        return claimsResolver.apply(claims);
    }

    //for retrieveing any information from token we will need the secret key
    public Claims getAllClaimsFromToken(String token, String jwtClientSecret) {
        return Jwts.parser().setSigningKey(jwtClientSecret).parseClaimsJws(token).getBody();
    }


    //check if the token has expired
    private Boolean isTokenExpired(String token, String jwtClientSecret) {
        final Date expiration = getExpirationDateFromToken(token, jwtClientSecret);
        return expiration.before(new Date());
    }


    public String generateJwtToken(Authentication authentication, String jwtClientSecret, long accessTokenValidity) {
        var userPrincipal = (UserDetails) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((System.currentTimeMillis() + (accessTokenValidity) * 1000)))
                .signWith(SignatureAlgorithm.HS512, jwtClientSecret)
                .compact();
    }

    //validate token
    public Boolean validateToken(String token, String systemUserName, String jwtClientSecret) {
        final String username = getUsernameFromToken(token, jwtClientSecret);
        return (username.equals(systemUserName) && !isTokenExpired(token, jwtClientSecret));
    }

    public boolean validateJwtToken(String authToken, String jwtClientSecret) {
        try {
            Jwts.parser().setSigningKey(jwtClientSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public static Claims getClaimsFromToken(String token, String jwtTokenVerifierKey) {
        return Jwts.parser()
                .setSigningKey(jwtTokenVerifierKey)
                .parseClaimsJws(token)
                .getBody();
    }
}
