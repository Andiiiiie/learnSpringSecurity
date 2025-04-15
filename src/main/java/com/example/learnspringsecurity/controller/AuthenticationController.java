package com.example.learnspringsecurity.controller;

import com.example.learnspringsecurity.dto.auth.LoginResponse;
import com.example.learnspringsecurity.dto.auth.LoginUserDto;
import com.example.learnspringsecurity.dto.auth.RegisterUserDto;
import com.example.learnspringsecurity.entity.User;
import com.example.learnspringsecurity.security.Response;
import com.example.learnspringsecurity.service.auth.AuthenticationService;
import com.example.learnspringsecurity.service.security.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
    private final JwtService jwtService;

    private final AuthenticationService authenticationService;

    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public Response<?> register(@RequestBody RegisterUserDto registerUserDto) {
       try{
           User registeredUser = authenticationService.signup(registerUserDto);
           return Response.send(HttpStatus.OK,"success",registeredUser);
       }catch (Exception e)
       {
           return Response.send(HttpStatus.BAD_REQUEST,"error",e.getMessage());
       }

    }

    @PostMapping("/login")
    public Response<?> authenticate(@RequestBody LoginUserDto loginUserDto) {
        try{
            User authenticatedUser = authenticationService.authenticate(loginUserDto);

            String jwtToken = jwtService.generateToken(authenticatedUser);

            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setToken(jwtToken);
            loginResponse.setExpiresIn(jwtService.getExpirationTime());

            return Response.send(HttpStatus.OK,"success",loginResponse);
        }catch (Exception e)
        {
            return Response.send(HttpStatus.BAD_REQUEST,"error",e.getMessage());
        }

    }

}
