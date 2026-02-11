package com.sbsc.security.core_security_starter.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Data
public class PropsReader {
//    @Value("${jwt.verifier.key}")
    private String jwtVerifierKey;

//    @Value("${jwt.accessTokenValiditySeconds}")
    private long accessTokenValidityInSeconds;

    @Value("${ignore.urls}")
    private String ignoreUrl;
}
