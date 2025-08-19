package org.example.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.example.entities.UserInfo;
import org.example.model.UserInfoDto;
import org.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Objects;
import java.util.UUID;

@Data
@AllArgsConstructor
@Component

public class UserDetailsServiceImpl implements UserDetailsService {
     @Autowired
    private final UserRepository userRepository;

     @Autowired
    private final PasswordEncoder passwordEncoder;

     @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

         UserInfo user = userRepository.findByUsername(username);
         if(user == null){
             throw new UsernameNotFoundException("could not found user");
         }
         return new CustomUserDetails(user);
     }

     public UserInfo checkIfUserAlreadyExist(UserInfoDto userInfoDto){
         return userRepository.findByUsername(userInfoDto.getUsername());
     }

     public Boolean signupUser(UserInfoDto userInfoDto){

         userInfoDto.setPassword(passwordEncoder.encode(userInfoDto.getPassword()));
         if(Objects.nonNull(checkIfUserAlreadyExist(userInfoDto))){
             return false;
         }
         String userId = UUID.randomUUID().toString();
         userRepository.save(new UserInfo(userId,userInfoDto.getUsername(),userInfoDto.getPassword(),new HashSet<>()));
         return true;
     }

     public Boolean validateUserCredentials(String email , String password){
         UserInfo user = userRepository.findByUsername(email);
         if(user == null){
             return false;
         }
         return passwordEncoder.matches(password, user.getPassword());
     }
}
