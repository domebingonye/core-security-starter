package com.sbsc.security.core_security_starter.filter;

import com.sbsc.security.core_security_starter.config.PropsReader;
import com.sbsc.security.core_security_starter.util.JwtTokenUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.*;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenUtil jwtUtils;
    public final PropsReader propsReader;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException{
        try {
            String jwt = parseJwt(httpServletRequest);
            if (jwt != null && jwtUtils.validateJwtToken(jwt, propsReader.getJwtVerifierKey())) {
                Claims claims = jwtUtils.getClaimsFromToken(jwt, propsReader.getJwtVerifierKey());
                GrantedAuthority authority = new SimpleGrantedAuthority((String)claims.get("role"));
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        buildUserDetails(claims), null, Collections.singleton(authority));
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }

    private static LinkedHashMap<String, Object> buildUserDetails(Claims claims){
        LinkedHashMap<String, Object> userDetails = new LinkedHashMap<>();
        userDetails.put("username", claims.getSubject());
        userDetails.put("role", claims.get("role"));
        return userDetails;
    }
}

