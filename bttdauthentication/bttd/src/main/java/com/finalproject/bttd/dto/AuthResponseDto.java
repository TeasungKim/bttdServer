package com.finalproject.bttd.dto;


import lombok.Data;

@Data
public class AuthResponseDto {
    private String accessToken;
    private String refreshToken;
    private String tokenType = "bearer ";

    public AuthResponseDto (String accessToken, String refreshToken){
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;

    }


}
