package com.finalproject.bttd.apicontroller;

import com.finalproject.bttd.dto.AuthResponseDto;
import com.finalproject.bttd.dto.LoginDto;
import com.finalproject.bttd.dto.TokenDto;
import com.finalproject.bttd.dto.UserDto;
import com.finalproject.bttd.entity.User;
import com.finalproject.bttd.repository.UserRepository;
import com.finalproject.bttd.security.CustomUserDetailService;
import com.finalproject.bttd.security.JWTGenerator;
import com.finalproject.bttd.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.CachingUserDetailsService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Slf4j
@RestController
public class ApiUserController {
    @Autowired
    private UserService userService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JWTGenerator jwtGenerator;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CustomUserDetailService customUserDetailService;



    @PostMapping("/api/user")
    public ResponseEntity<String> createUser(@RequestBody UserDto userDto) {

        User created = userService.create(userDto);
        return new ResponseEntity<>("{\"data\":{\"success\":true}}", HttpStatus.OK);
    }



    @PostMapping("/api/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody LoginDto loginDto){
        log.info("1 : "+ loginDto.getUser_name());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
      Authentication authentication = authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(loginDto.getUser_name(), loginDto.getUser_password()));
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
     //   SecurityContextHolder.getContext().setAuthentication(authentication);
        TokenDto token = jwtGenerator.generateToken(authentication);
       // TokenDto tokenDto = jwtGenerator.generateToken(authentication);
       String result = token.getAccessToken();
       String result1 = token.getRefreshToken();

        return new ResponseEntity<>(new AuthResponseDto(result, result1), HttpStatus.OK);
    }

 @GetMapping("/api/reissue")
    public ResponseEntity<AuthResponseDto> reIssue(Principal principal){
     log.info("1 : "+ principal.getName());
      String user_name = principal.getName();

        userRepository.findByuser_name(user_name);
        if (user_name != null){
            UserDetails userDetails = customUserDetailService.loadUserByUsername(user_name);
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            TokenDto token = jwtGenerator.generateToken(authenticationToken);
            String result = token.getAccessToken();
            String result1 = token.getRefreshToken();

            return new ResponseEntity<>(new AuthResponseDto(result, result1),HttpStatus.OK);
        }
        return null;
 }





//
}
