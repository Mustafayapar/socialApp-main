package com.project.questapp.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;

import javax.crypto.SecretKey;

@Component
public class JwtTokenProvider {

	@Value("${questapp.app.secret}")
	private String APP_SECRET;
	
	@Value("${questapp.expires.in}")
	private long EXPIRES_IN;


	private SecretKey getSecretKey() {
		return Keys.hmacShaKeyFor(APP_SECRET.getBytes(StandardCharsets.UTF_8));
	}



	public String generateJwtTokenByUserId(Authentication auth) {
		return generateJwtToken( auth);
	}


	public String generateJwtToken(Authentication auth) {
		JwtUserDetails userDetails = (JwtUserDetails) auth.getPrincipal();
		Date now = new Date();
		Date expireDate = new Date(now.getTime() + EXPIRES_IN);

		return Jwts.builder()
				.setSubject(Long.toString(userDetails.getId()))
				.setIssuedAt(now)
				.setExpiration(expireDate)
				.signWith(getSecretKey(), SignatureAlgorithm.HS512)
				.compact();
	}
	
	public String generateJwtTokenByUserId(Long userId) {

		Date now = new Date();
		Date expireDate = new Date(now.getTime() + EXPIRES_IN);

		return Jwts.builder()
				.setSubject(Long.toString(userId))
				.setIssuedAt(new Date())
				.setExpiration(expireDate)
				.signWith(getSecretKey(), SignatureAlgorithm.HS512)
				.compact();
	}

	
	Long getUserIdFromJwt(String token) {
		Claims claims = Jwts.parserBuilder()
				.setSigningKey(getSecretKey())
				.build()
				.parseClaimsJws(token)
				.getBody();
		return Long.parseLong(claims.getSubject());
	}

	public boolean validateToken(String token) {
		try {
			Claims claims = Jwts.parserBuilder()
					.setSigningKey(getSecretKey())
					.build()
					.parseClaimsJws(token).getBody();
			return claims.getExpiration().after(new Date());
		} catch (JwtException | IllegalArgumentException e) {
			return false; // tüm JWT hataları burada birleşti
		}
	}


	private boolean isTokenExpired(String token) {
		Date expiration = Jwts.parserBuilder()
				.setSigningKey(getSecretKey())
				.build()
				.parseClaimsJws(token)
				.getBody()
				.getExpiration();
		return expiration.before(new Date());
	}

}
