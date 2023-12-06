package com.finalproject.bttd.security;

import com.finalproject.bttd.dto.TokenDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Slf4j
@Component
public class JWTGenerator {


    public TokenDto generateToken(Authentication authentication){
        String access_username = authentication.getName();
        Date access_currentDate = new Date();
        Date access_expireDate = new Date(access_currentDate.getTime() + SecurityContents.JWT_EXPIRATION);
        log.info("generateToken access_currentDate : " + access_currentDate);
        log.info("generateToken access_expireDate: " + access_expireDate);

        String access_token = Jwts.builder().setSubject(access_username).setIssuedAt(new Date()).setExpiration(access_expireDate)
                .signWith(SignatureAlgorithm.HS512, SecurityContents.JWT_SECRET).compact();

        String refreshToken = authentication.getName();
        Date refresh_currentDate = new Date();
        Date refresh_expireDate = new Date(refresh_currentDate.getTime() + SecurityContents.RFT_EXPIRATION);
//
        String refresh_token = Jwts.builder().setSubject(refreshToken).setIssuedAt(new Date()).setExpiration(refresh_expireDate)
                .signWith(SignatureAlgorithm.HS512, SecurityContents.JWT_SECRET).compact();
            // RefreshToken 만드는 메소드.
        return new TokenDto(access_token, refresh_token); // tokenDto형식으로 반환

    }
public  String getUserNameFromJWT(String token){
        Claims claims = Jwts.parser().setSigningKey(SecurityContents.JWT_SECRET).parseClaimsJws(token).getBody();
        return claims.getSubject();
}

public boolean validateToken (String token){
        log.info("validateToken 1 : " + token);
        try {
            Jwts.parser().setSigningKey(SecurityContents.JWT_SECRET).parseClaimsJws(token);
            return true;

        } catch(Exception ex){
            log.info("validateToken Error : " + ex);
           throw new SignatureException("invalid token");

        }

}



//
}
