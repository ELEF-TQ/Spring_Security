package com.eleftq.sec.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SignupRequest(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 20)
        String username,
        @NotBlank(message = "Password is required")
        @Size(min = 6, max = 40)
        String password


) {}
