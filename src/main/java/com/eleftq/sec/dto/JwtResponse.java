package com.eleftq.sec.dto;

import java.util.Set;

public record JwtResponse(String token, String refreshToken, String username, String role, Set<String> permissions) {}
