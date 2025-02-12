package com.eleftq.sec.dto;

import java.util.List;

public record JwtResponse(
        String token,
        String type,
        Long id,
        String username,
        List<String> roles
) {
    public JwtResponse(String token) {
        this(token, "Bearer", null, null, null);
    }
}