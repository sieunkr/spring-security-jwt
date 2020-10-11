package com.example.demo.service;

import com.example.demo.controller.dto.LoginDto;
import com.example.demo.security.CustomUserDetails;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@RequiredArgsConstructor
public class AuthService {


    public Authentication test(LoginDto loginDto) {

        /*
        var authenticationToken = new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return authentication;

         */

        //JwtAuthenticationToken --> Oauth 디펜던시 추가해야 하는 듯...

        UserDetails userDetails = CustomUserDetails.builder()
                .ID(loginDto.getUsername())
                .NAME(loginDto.getUsername())
                .AUTHORITY("ROLE_USER")
                .build();

        //Claims claims = jwtUtil.getClaims(token.substring("Bearer ".length()));

        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, loginDto.getPassword(), userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return authentication;
    }

}