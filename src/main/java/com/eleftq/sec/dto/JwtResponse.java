package com.eleftq.sec.dto;

import java.util.List;
import java.util.Set;

public record JwtResponse(String token, String username, String role , Set<String> permissions) {}
