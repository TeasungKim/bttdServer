package com.finalproject.bttd.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private CustomUserDetailService customUserDetailService;
    private JwtAuthEntryPoint jwtAuthEntryPoint;

    private AuthenticationEntryPoint entryPoint;
@Autowired
    public SecurityConfig(CustomUserDetailService customUserDetailService, JwtAuthEntryPoint jwtAuthEntryPoint) {
        this.customUserDetailService = customUserDetailService;
        this.jwtAuthEntryPoint = jwtAuthEntryPoint;
    }





@Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {

    log.info("securityFilterChain 2 : ");
        http.csrf().disable().exceptionHandling().authenticationEntryPoint(jwtAuthEntryPoint)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
    .authorizeRequests().antMatchers("/api/login","/api/user").permitAll().anyRequest().authenticated()
                .and().httpBasic();
    log.info("securityFilterChain 3 : ");
    log.info("securityFilterChain 1 : ");
    http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class).
            exceptionHandling(handler -> handler.authenticationEntryPoint(entryPoint));
        return http.build();

}


//@Bean
//    public UserDetailsService user(){
//    UserDetails admin = User.builder().username("admin").password("password").roles("ADMIN").build();
//    UserDetails user = User.builder().username("user").password("password").roles("USER").build();
//
//    return new InMemoryUserDetailsManager(admin, user);
//}

@Bean
    public AuthenticationManager authenticationManager (AuthenticationConfiguration authenticationConfiguration) throws Exception {

    return authenticationConfiguration.getAuthenticationManager();
}

@Bean
    PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
}

@Bean
    public JWTAuthenticationFilter jwtAuthenticationFilter(){
    return new JWTAuthenticationFilter();
}

//
}
