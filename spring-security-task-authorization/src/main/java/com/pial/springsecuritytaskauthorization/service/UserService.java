package com.pial.springsecuritytaskauthorization.service;


import com.pial.springsecuritytaskauthorization.model.UserDto;

public interface UserService {
    UserDto createUser(UserDto user) throws Exception;
    UserDto getUser(String email);

    UserDto getUserByUserId(String id) throws Exception;

}