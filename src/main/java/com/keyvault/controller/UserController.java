package com.keyvault.controller;

import com.keyvault.dto.UserResponse;
import com.keyvault.entity.User;
import com.keyvault.exception.ResourceNotFoundException;
import com.keyvault.repository.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "2. User Management", description = "Authenticated user profile endpoints")
@SecurityRequirement(name = "BearerAuth")
public class UserController {

    private final UserRepository userRepository;
    private final com.keyvault.service.AuthService authService;

    @GetMapping("/me")
    @Operation(summary = "Get Current User Profile", description = "Retrieve details of the currently authenticated JWT user.")
    public ResponseEntity<UserResponse> getCurrentUser(Authentication authentication) {
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return ResponseEntity.ok(UserResponse.fromEntity(user));
    }

    @org.springframework.web.bind.annotation.PatchMapping("/me")
    @Operation(summary = "Update User Profile", description = "Update the profile information (e.g. name) of the currently authenticated user.")
    public ResponseEntity<UserResponse> updateProfile(
            Authentication authentication,
            @jakarta.validation.Valid @org.springframework.web.bind.annotation.RequestBody com.keyvault.dto.UpdateProfileRequest request
    ) {
        UserResponse response = authService.updateProfile(authentication.getName(), request);
        return ResponseEntity.ok(response);
    }

    @org.springframework.web.bind.annotation.PutMapping("/me/password")
    @Operation(summary = "Change Password", description = "Change the password for the currently authenticated user.")
    public ResponseEntity<java.util.Map<String, String>> changePassword(
            Authentication authentication,
            @jakarta.validation.Valid @org.springframework.web.bind.annotation.RequestBody com.keyvault.dto.ChangePasswordRequest request
    ) {
        authService.changePassword(authentication.getName(), request);
        return ResponseEntity.ok(java.util.Map.of("message", "Password changed successfully"));
    }
}
