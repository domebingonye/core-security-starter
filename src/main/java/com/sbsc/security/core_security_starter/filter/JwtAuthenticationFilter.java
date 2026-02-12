package com.sbsc.security.core_security_starter.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sbsc.core_security_starter.constant.CommonConstants;
import com.sbsc.security.core_security_starter.config.CustomAuthenticationToken;
import com.sbsc.security.core_security_starter.util.JwtTokenUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader(CommonConstants.AUTHORIZATION_KEY);

        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {

            String token = header.substring(7);

            Claims claims = validateJwtToken(token);
            String username = claims.getSubject();

            List<String> roles = claims.get("roles", List.class);
            if (roles == null) {
                roles = List.of();
            }

            List<GrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

            CustomAuthenticationToken authentication = new CustomAuthenticationToken(token, username, null, authorities);

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    public Claims validateJwtToken(String token) {

        boolean isValidToken = JwtTokenUtil.validateJwtToken(token);

        if (!isValidToken) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid User");
        }

        return JwtTokenUtil.getClaimsFromToken(token);
    }
}

