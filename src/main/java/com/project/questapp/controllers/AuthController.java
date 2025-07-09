package com.project.questapp.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.project.questapp.entities.RefreshToken;
import com.project.questapp.entities.User;
import com.project.questapp.requests.RefreshRequest;
import com.project.questapp.requests.UserRequest;
import com.project.questapp.responses.AuthResponse;
import com.project.questapp.security.JwtTokenProvider;
import com.project.questapp.services.RefreshTokenService;
import com.project.questapp.services.UserService;

@RestController
@RequestMapping("/auth")
public class AuthController {
	
	private AuthenticationManager authenticationManager;
	
	private JwtTokenProvider jwtTokenProvider;
	
	private UserService userService;
	
	private PasswordEncoder passwordEncoder;

	private RefreshTokenService refreshTokenService;
	
    public AuthController(AuthenticationManager authenticationManager, UserService userService, 
    		PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider, RefreshTokenService refreshTokenService) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenService = refreshTokenService;
    }

	@PostMapping("/login")
	public ResponseEntity<AuthResponse> login(@RequestBody UserRequest loginRequest) {
		try {
			// Validate input
			if (loginRequest.getUserName() == null || loginRequest.getUserName().trim().isEmpty()) {
				AuthResponse errorResponse = new AuthResponse();
				errorResponse.setMessage("Username is required.");
				return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
			}

			if (loginRequest.getPassword() == null || loginRequest.getPassword().trim().isEmpty()) {
				AuthResponse errorResponse = new AuthResponse();
				errorResponse.setMessage("Password is required.");
				return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
			}

			UsernamePasswordAuthenticationToken authToken =
					new UsernamePasswordAuthenticationToken(loginRequest.getUserName(), loginRequest.getPassword());

			Authentication auth = authenticationManager.authenticate(authToken);
			SecurityContextHolder.getContext().setAuthentication(auth);

			String jwtToken = jwtTokenProvider.generateJwtToken(auth);
			User user = userService.getOneUserByUserName(loginRequest.getUserName());

			AuthResponse authResponse = new AuthResponse();
			authResponse.setMessage("Login successful.");
			authResponse.setAccessToken("Bearer " + jwtToken);
			authResponse.setRefreshToken(refreshTokenService.createRefreshToken(user));
			authResponse.setUserId(user.getId());

			return new ResponseEntity<>(authResponse, HttpStatus.OK);

		} catch (BadCredentialsException e) {
			AuthResponse errorResponse = new AuthResponse();
			errorResponse.setMessage("Invalid username or password.");
			return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
		} catch (DisabledException e) {
			AuthResponse errorResponse = new AuthResponse();
			errorResponse.setMessage("Account is disabled.");
			return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
		} catch (LockedException e) {
			AuthResponse errorResponse = new AuthResponse();
			errorResponse.setMessage("Account is locked.");
			return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
		} catch (Exception e) {
			AuthResponse errorResponse = new AuthResponse();
			errorResponse.setMessage("Login failed. Please try again.");
			return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@PostMapping("/register")
	public ResponseEntity<AuthResponse> register(@RequestBody UserRequest registerRequest) {
		try {
			AuthResponse authResponse = new AuthResponse();

			// Input validation
			if (registerRequest.getUserName() == null || registerRequest.getUserName().trim().isEmpty()) {
				authResponse.setMessage("Username is required.");
				return new ResponseEntity<>(authResponse, HttpStatus.BAD_REQUEST);
			}

			if (registerRequest.getPassword() == null || registerRequest.getPassword().length() < 3) {
				authResponse.setMessage("Password must be at least 3 characters long.");
				return new ResponseEntity<>(authResponse, HttpStatus.BAD_REQUEST);
			}

			// Username validation (optional: add pattern validation)
			if (registerRequest.getUserName().length() < 3) {
				authResponse.setMessage("Username must be at erleast 3 characts long.");
				return new ResponseEntity<>(authResponse, HttpStatus.BAD_REQUEST);
			}

			// Check if username already exists
			if (userService.getOneUserByUserName(registerRequest.getUserName()) != null) {
				authResponse.setMessage("Username already in use.");
				return new ResponseEntity<>(authResponse, HttpStatus.CONFLICT);
			}

			// Create new user
			User user = new User();
			user.setUserName(registerRequest.getUserName().trim());
			user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
			User savedUser = userService.saveOneUser(user);

			// Auto-login the new user
			UsernamePasswordAuthenticationToken authToken =
					new UsernamePasswordAuthenticationToken(registerRequest.getUserName(), registerRequest.getPassword());
			Authentication auth = authenticationManager.authenticate(authToken);
			SecurityContextHolder.getContext().setAuthentication(auth);

			String jwtToken = jwtTokenProvider.generateJwtToken(auth);

			authResponse.setMessage("User successfully registered and logged in.");
			authResponse.setAccessToken("Bearer " + jwtToken);
			authResponse.setRefreshToken(refreshTokenService.createRefreshToken(savedUser));
			authResponse.setUserId(savedUser.getId());

			return new ResponseEntity<>(authResponse, HttpStatus.CREATED);

		} catch (Exception e) {
			AuthResponse errorResponse = new AuthResponse();
			errorResponse.setMessage("Registration failed. Please try again.");
			return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	
	@PostMapping("/refresh")
	public ResponseEntity<AuthResponse> refresh(@RequestBody RefreshRequest refreshRequest) {
		AuthResponse response = new AuthResponse();
		RefreshToken token = refreshTokenService.getByUser(refreshRequest.getUserId());
		if(token.getToken().equals(refreshRequest.getRefreshToken()) &&
				!refreshTokenService.isRefreshExpired(token)) {

			User user = token.getUser();
			String jwtToken = jwtTokenProvider.generateJwtTokenByUserId(user.getId());
			response.setMessage("token successfully refreshed.");
			response.setAccessToken("Bearer " + jwtToken);
			response.setUserId(user.getId());
			return new ResponseEntity<>(response, HttpStatus.OK);		
		} else {
			response.setMessage("refresh token is not valid.");
			return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
		}
		
	}
	

}
