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

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    public AuthResponse register(RegisterRequest request) {
        String normalizedEmail = normalizeEmail(request.getEmail());
        if (userRepository.findByEmail(normalizedEmail).isPresent()) {
            throw new DuplicateEmailException("Email is already registered");
        }

        User user = User.builder()
                .name(request.getName().trim())
                .email(normalizedEmail)
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
        String normalizedEmail = normalizeEmail(request.getEmail());
        User user = userRepository.findByEmail(normalizedEmail)
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

    public com.keyvault.dto.UserResponse updateProfile(String email, com.keyvault.dto.UpdateProfileRequest request) {
        User user = userRepository.findByEmail(normalizeEmail(email))
                .orElseThrow(() -> new com.keyvault.exception.ResourceNotFoundException("User not found"));

        user.setName(request.getName().trim());
        User updated = userRepository.save(user);
        return com.keyvault.dto.UserResponse.fromEntity(updated);
    }

    public void changePassword(String email, com.keyvault.dto.ChangePasswordRequest request) {
        User user = userRepository.findByEmail(normalizeEmail(email))
                .orElseThrow(() -> new com.keyvault.exception.ResourceNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadCredentialsException("Current password does not match");
        }

        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new IllegalArgumentException("New password must be different from current password");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    private static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
