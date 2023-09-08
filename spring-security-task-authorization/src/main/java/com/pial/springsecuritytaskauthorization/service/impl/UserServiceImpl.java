package com.pial.springsecuritytaskauthorization.service.impl;


import com.pial.springsecuritytaskauthorization.constants.AppConstants;
import com.pial.springsecuritytaskauthorization.entity.UserEntity;
import com.pial.springsecuritytaskauthorization.model.UserDto;
import com.pial.springsecuritytaskauthorization.repository.UserRepository;
import com.pial.springsecuritytaskauthorization.service.UserService;
import com.pial.springsecuritytaskauthorization.utils.JWTUtils;
import org.modelmapper.ModelMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;

@Service
@Transactional
public class UserServiceImpl implements UserService, UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public UserDto createUser(UserDto user) throws Exception {
        if(userRepository.findByEmail(user.getEmail()).isPresent())
            throw new Exception("Record already exists");

        ModelMapper modelMapper = new ModelMapper();
        UserEntity userEntity = new UserEntity();
        userEntity.setEmail(user.getEmail());
        userEntity.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        String publicUserId = JWTUtils.generateUserID(10);
        userEntity.setUserId(publicUserId);
        userEntity.setRole(user.getRole());
        UserEntity storedUserDetails = userRepository.save(userEntity);
        UserDto returnedValue = modelMapper.map(storedUserDetails,UserDto.class);
        String accessToken = JWTUtils.generateToken(userEntity.getEmail());
        returnedValue.setAccessToken(AppConstants.TOKEN_PREFIX + accessToken);
        return returnedValue;
    }




    @Override
    public UserDto getUser(String email) {
        UserEntity userEntity = userRepository.findByEmail(email).get();
        if(userEntity == null) throw new UsernameNotFoundException("No record found");
        UserDto returnValue = new UserDto();
        BeanUtils.copyProperties(userEntity,returnValue);
        return returnValue;
    }

    @Override
    public UserDto getUserByUserId(String userId) throws Exception {
        UserDto returnValue = new UserDto();
        UserEntity userEntity = userRepository.findByUserId(userId).orElseThrow(Exception::new);
        BeanUtils.copyProperties(userEntity,returnValue);
        return returnValue;
    }
   @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByEmail(email).get();
        if(userEntity==null) throw new UsernameNotFoundException(email);
        return new User(userEntity.getEmail(),userEntity.getPassword(),
                true,true,true,true,new ArrayList<>());
    }

}