package com.sbsc.security.core_security_starter.util;

import com.sbsc.core_security_starter.constant.CommonConstants;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.Serializable;

@Component
public class JwtTokenUtil implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(JwtTokenUtil.class);

    public static Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(CommonConstants.CLIENT_SECRET)
                .parseClaimsJws(token)
                .getBody();
    }

    public static boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(CommonConstants.CLIENT_SECRET).parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }catch (Exception e){
            log.error(e.getMessage(), e);
        }
        return false;
    }
}
