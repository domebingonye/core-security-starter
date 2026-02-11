package com.sbsc.security.core_security_starter.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class BaseResponse {
    private String message;
    private String code;
    private int statusCode;
    private Object response;

    public BaseResponse(String message){
        this.message = message;
    }

    public BaseResponse(String code, String message){
        this.code = code;
        this.message = message;
    }

    public BaseResponse(String code, String message, int statusCode, Object response){
        this.code = code;
        this.message = message;
        this.statusCode = statusCode;
        this.response = response;
    }
}
