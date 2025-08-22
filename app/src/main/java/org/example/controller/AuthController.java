package org.example.controller;

import lombok.AllArgsConstructor;
import org.example.entities.RefreshToken;
import org.example.model.UserInfoDto;
import org.example.request.RefreshTokenRequestDTO;
import org.example.response.JwtResponseDTO;
import org.example.service.JwtService;
import org.example.service.RefreshTokenService;
import org.example.service.UserDetailsServiceImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
public class AuthController {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserDetailsServiceImpl userDetailsService;

    @PostMapping("/auth/v1/signup")
    public ResponseEntity<?> signup(@RequestBody UserInfoDto userInfoDto) {
        try {
            Boolean isSignUpSuccessful = userDetailsService.signupUser(userInfoDto);
            if (Boolean.FALSE.equals(isSignUpSuccessful)) {
                return new ResponseEntity<>("Already Exist", HttpStatus.BAD_REQUEST);
            }

            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userInfoDto.getUsername());
            String jwtToken = jwtService.generateToken(userInfoDto.getUsername());

            return new ResponseEntity<>(
                    JwtResponseDTO.builder()
                            .accessToken(jwtToken)
                            .token(refreshToken.getToken())
                            .build(),
                    HttpStatus.OK
            );
        } catch (Exception ex) {
            return new ResponseEntity<>("Exception in User Service", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/auth/v1/refreshToken")
    public JwtResponseDTO refreshToken(@RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO) {
        return refreshTokenService.findByToken(refreshTokenRequestDTO.getToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUserInfo)
                .map(userInfo -> {
                    String accessToken = jwtService.generateToken(userInfo.getUsername());
                    return JwtResponseDTO.builder()
                            .accessToken(accessToken)
                            .token(refreshTokenRequestDTO.getToken())
                            .build();
                })
                .orElseThrow(() -> new RuntimeException("Refresh Token is not in DB..!!"));
    }
}
