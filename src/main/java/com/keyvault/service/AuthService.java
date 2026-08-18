package com.keyvault.service;

import com.keyvault.config.JwtUtils;
import com.keyvault.dto.AuthResponse;
import com.keyvault.dto.LoginRequest;
import com.keyvault.dto.RegisterRequest;
import com.keyvault.entity.User;
import com.keyvault.exception.DuplicateEmailException;
import com.keyvault.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new DuplicateEmailException("Email is already registered");
        }

        User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role("ROLE_USER")
                .build();

        userRepository.save(user);

        String token = jwtUtils.generateToken(user.getEmail());
        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid email or password");
        }

        String token = jwtUtils.generateToken(user.getEmail());
        return AuthResponse.builder()
                .accessToken(token)
                .tokenType("Bearer")
                .build();
    }
}
