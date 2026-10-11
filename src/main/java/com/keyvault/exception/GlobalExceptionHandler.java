package com.keyvault.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<com.keyvault.dto.ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(com.keyvault.dto.ErrorResponse.builder()
                .status(HttpStatus.FORBIDDEN.value())
                .error("Forbidden")
                .message("Forbidden")
                .build());
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<com.keyvault.dto.ErrorResponse> handleResourceNotFound(ResourceNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(com.keyvault.dto.ErrorResponse.builder()
                .status(HttpStatus.NOT_FOUND.value())
                .error(ex.getMessage())
                .message(ex.getMessage())
                .build());
    }

    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<com.keyvault.dto.ErrorResponse> handleDuplicateEmail(DuplicateEmailException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(com.keyvault.dto.ErrorResponse.builder()
                .status(HttpStatus.CONFLICT.value())
                .error(ex.getMessage())
                .message(ex.getMessage())
                .build());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<com.keyvault.dto.ErrorResponse> handleBadCredentials(BadCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(com.keyvault.dto.ErrorResponse.builder()
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Invalid email or password")
                .message("Invalid email or password")
                .build());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<com.keyvault.dto.ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(com.keyvault.dto.ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation failed")
                .message("Validation failed")
                .details(errors)
                .build());
    }

    @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class})
    public ResponseEntity<com.keyvault.dto.ErrorResponse> handleBadRequestExceptions(RuntimeException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(com.keyvault.dto.ErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())
                .error(ex.getMessage())
                .message(ex.getMessage())
                .build());
    }
}
