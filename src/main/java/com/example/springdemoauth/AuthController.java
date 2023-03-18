package com.example.springdemoauth;

import com.example.springdemoauth.exception.LoginException;
import com.example.springdemoauth.exception.RegistrationException;
import com.example.springdemoauth.model.ErrorResponse;
import com.example.springdemoauth.model.TokenResponse;
import com.example.springdemoauth.model.User;
import com.example.springdemoauth.service.ClientService;
import com.example.springdemoauth.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final ClientService clientService;
    private final TokenService tokenService;

    @PostMapping
    public ResponseEntity<String> register(@RequestBody User user) {
        clientService.register(user.getClientId(), user.getClientSecret());
        return ResponseEntity.ok("Registered");
    }

    @PostMapping("/token")
    public TokenResponse getToken(@RequestBody User user) {
        clientService.checkCredentials(
                user.getClientId(), user.getClientSecret());
        return new TokenResponse(
                tokenService.generateToken(user.getClientId()));
    }

    @ExceptionHandler({RegistrationException.class, LoginException.class})
    public ResponseEntity<ErrorResponse> handleUserRegistrationException(RuntimeException ex) {
        return ResponseEntity
                .badRequest()
                .body(new ErrorResponse(ex.getMessage()));
    }
}
