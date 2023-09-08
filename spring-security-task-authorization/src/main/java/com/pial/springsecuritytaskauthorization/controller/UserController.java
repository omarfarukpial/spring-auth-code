package com.pial.springsecuritytaskauthorization.controller;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.pial.springsecuritytaskauthorization.constants.AppConstants;
import com.pial.springsecuritytaskauthorization.model.UserDto;
import com.pial.springsecuritytaskauthorization.model.UserLoginReqModel;
import com.pial.springsecuritytaskauthorization.service.UserService;
import com.pial.springsecuritytaskauthorization.service.impl.UserServiceImpl;
import com.pial.springsecuritytaskauthorization.utils.JWTUtils;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserServiceImpl userServiceImpl;

    @Autowired
    private AuthenticationManager authenticationManager;




    @GetMapping("/hello")
    public String hello(){
        return "Hello";
    }

    @GetMapping("/hello2")
    public String hello2(){
        return "Hello2";
    }
    @PostMapping("/registration")
    public ResponseEntity<?> register (@RequestBody UserDto userDto) {
        try {
            UserDto createdUser = userServiceImpl.createUser(userDto);
            String accessToken = JWTUtils.generateToken(createdUser.getEmail());
            Map<String, Object> response = new HashMap<>();
            response.put("user", createdUser);
            response.put(AppConstants.HEADER_STRING, AppConstants.TOKEN_PREFIX + accessToken);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
//            return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/login")
    public void login(@RequestBody UserLoginReqModel userLoginReqModel, HttpServletResponse response) throws IOException {
        try {
            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userLoginReqModel.getEmail(), userLoginReqModel.getPassword()));

            // If authentication is successful, generate a JWT token
            if (authentication.isAuthenticated()) {
                UserDto userDto = userServiceImpl.getUser(userLoginReqModel.getEmail());
                String accessToken = JWTUtils.generateToken(userDto.getEmail());

                Map<String, Object> responseBody = new HashMap<>();
                responseBody.put("userId", userDto.getUserId());
                responseBody.put("email", userDto.getEmail());
                responseBody.put(AppConstants.HEADER_STRING, AppConstants.TOKEN_PREFIX + accessToken);

                response.setContentType("application/json");
                response.getWriter().write(new ObjectMapper().writeValueAsString(responseBody));
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "Authentication failed");
                errorResponse.put("message", "Invalid email or password");
                response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
            }
        } catch (UsernameNotFoundException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "User not found");
            response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
        }
    }




}
