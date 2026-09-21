package com.keyvault.service;

import com.keyvault.config.JwtUtils;
import com.keyvault.dto.AuthResponse;
import com.keyvault.dto.LoginRequest;
import com.keyvault.dto.RegisterRequest;
import com.keyvault.entity.User;
import com.keyvault.exception.DuplicateEmailException;
import com.keyvault.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuthService}. The repository is mocked; the password encoder and
 * JWT utility are real, so password hashing and token issuance are genuinely exercised.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final String EMAIL = "member@example.com";
    private static final String RAW_PASSWORD = "password123";
    private static final String TEST_SECRET = "keyvault-unit-test-signing-secret-0123456789abcdef";

    @Mock
    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;
    private JwtUtils jwtUtils;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        jwtUtils = new JwtUtils(TEST_SECRET, 86_400_000L);
        authService = new AuthService(userRepository, passwordEncoder, jwtUtils);
    }

    private User existingUser() {
        return User.builder()
                .id(1L)
                .name("Member")
                .email(EMAIL)
                .password(passwordEncoder.encode(RAW_PASSWORD))
                .role("ROLE_USER")
                .build();
    }

    @Test
    @DisplayName("Registration stores a BCrypt hash, never the raw password")
    void registerHashesPassword() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        AuthResponse response = authService.register(RegisterRequest.builder()
                .name("Member").email(EMAIL).password(RAW_PASSWORD).build());

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User persisted = captor.getValue();

        assertNotEquals(RAW_PASSWORD, persisted.getPassword());
        assertTrue(passwordEncoder.matches(RAW_PASSWORD, persisted.getPassword()));
        assertEquals("ROLE_USER", persisted.getRole());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(EMAIL, jwtUtils.getEmailFromToken(response.getAccessToken()));
    }

    @Test
    @DisplayName("Registering an email that already exists is a conflict, not a new account")
    void registerRejectsDuplicateEmail() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(existingUser()));

        RegisterRequest request = RegisterRequest.builder()
                .name("Impostor").email(EMAIL).password(RAW_PASSWORD).build();

        assertThrows(DuplicateEmailException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Login with correct credentials issues a token carrying the user email")
    void loginIssuesTokenForValidCredentials() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(existingUser()));

        AuthResponse response = authService.login(
                LoginRequest.builder().email(EMAIL).password(RAW_PASSWORD).build());

        assertTrue(jwtUtils.validateToken(response.getAccessToken()));
        assertEquals(EMAIL, jwtUtils.getEmailFromToken(response.getAccessToken()));
    }

    @Test
    @DisplayName("A wrong password is rejected")
    void loginRejectsWrongPassword() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(existingUser()));

        LoginRequest request = LoginRequest.builder().email(EMAIL).password("not-the-password").build();

        assertThrows(BadCredentialsException.class, () -> authService.login(request));
    }

    @Test
    @DisplayName("An unknown email fails the same way as a wrong password, revealing nothing")
    void loginRejectsUnknownEmail() {
        when(userRepository.findByEmail("ghost@example.com")).thenReturn(Optional.empty());

        LoginRequest request = LoginRequest.builder().email("ghost@example.com").password(RAW_PASSWORD).build();

        assertThrows(BadCredentialsException.class, () -> authService.login(request));
    }
}
