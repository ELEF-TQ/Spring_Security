package com.eleftq.sec.util;

import com.eleftq.sec.security.services.UserDetailsImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class JwtUtils {
    private static final Set<String> blacklist = ConcurrentHashMap.newKeySet();
    private final SecretKey jwtSecret;
    private final JwtParser jwtParser;

    @Value("${app.jwt.expiration.ms}")
    private int jwtExpirationMs;

    private static final int REQUIRED_KEY_LENGTH = 64;
    private static final long REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000; // 7 days


    public JwtUtils(@Value("${app.jwt.secret}") String base64Secret, @Value("${app.jwt.expiration.ms}") int jwtExpirationMs) {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
            if (keyBytes.length != REQUIRED_KEY_LENGTH) {
                throw new IllegalArgumentException("Invalid key size");
            }
            this.jwtSecret = Keys.hmacShaKeyFor(keyBytes);
            this.jwtParser = Jwts.parser()
                    .verifyWith(jwtSecret)
                    .build();
            this.jwtExpirationMs = jwtExpirationMs;
        } catch (Exception e) {
            throw new RuntimeException("JWT initialization failed", e);
        }
    }

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .subject(userPrincipal.getUsername()) // Using subject()
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(jwtSecret, Jwts.SIG.HS512)  // Using enum from Jwts.SIG
                .compact();
    }

    public String generateRefreshToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        // Generate secret key from the secret string
        Key key = Keys.hmacShaKeyFor(jwtSecret.getEncoded());

        return Jwts.builder()
                .subject(userPrincipal.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(key)  // Sign with the generated key
                .compact();
    }



    public boolean validateJwtToken(String token) {
        try {
            return !blacklist.contains(token) && parseToken(token) != null;
        } catch (Exception e) {
            // Handle specific exceptions here
            return false;
        }
    }

    private Claims parseToken(String token) {
        return jwtParser.parseSignedClaims(token).getPayload();
    }

    public void addToBlacklist(String token) {
        blacklist.add(token);
    }

    public String getUserNameFromJwtToken(String token) {
        return parseToken(token).getSubject();
    }
}