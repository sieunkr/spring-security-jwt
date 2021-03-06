package com.example.demo.controller;

import com.example.demo.controller.dto.LoginDto;
import com.example.demo.security.JWTFilter;
import com.example.demo.security.TokenProvider;
import com.example.demo.service.AuthService;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/v1/login")
@RequiredArgsConstructor
public class LoginController {


    private final TokenProvider tokenProvider;
    //private final AuthenticationManager authenticationManager;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final AuthService authService;

    @PostMapping
    public ResponseEntity<JWTToken> authorize(@Valid @RequestBody LoginDto loginDto) {


        /*
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
         */


        /*
        var authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
         */

        Authentication authentication = authService.test(loginDto);

        boolean rememberMe = (loginDto.isRememberMe() == null) ? false : loginDto.isRememberMe();
        String jwt = tokenProvider.createToken(authentication, rememberMe);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, jwt);

        return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
    }


    /**
     * Object to return as body in JWT Authentication.
     */
    static class JWTToken {

        private String idToken;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

        @JsonProperty("id_token")
        String getIdToken() {
            return idToken;
        }

        void setIdToken(String idToken) {
            this.idToken = idToken;
        }
    }


}
