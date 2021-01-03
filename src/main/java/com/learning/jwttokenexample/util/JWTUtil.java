package com.learning.jwttokenexample.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JWTUtil {
	private String SECRET_KEY = "secret";
	public String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}
	public <T> T extractClaim(String token,Function<Claims,T> claimsResolver) {
		/* Extracts the sent data and resolves them. It is being used by extractUserName, extractExpiration, so on */
		final Claims claims=extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	private Claims extractAllClaims(String token) {
		return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJwt(token).getBody();
	}
	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
	public String generateToken(UserDetails userDetails) {/* Create JWT based on UserDetails*/
		Map<String, Object> claims= new HashMap<>();
		return createToken(claims,userDetails.getUsername());
	}
	private String createToken(Map<String,Object> claims,String subject) {
		/*subject is the person , issued at is the current date, expiration date is 10 hours*/
		/*Signing the token uses, the SignatureAlgorithm HS256 and the Secret key provided*/
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+1000*60*60*10))
				.signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
	}
	public Boolean validateToken(String token,UserDetails userDetails) {
		final String username = extractUserName(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
}
