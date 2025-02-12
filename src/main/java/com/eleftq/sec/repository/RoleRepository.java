package com.eleftq.sec.repository;

import com.eleftq.sec.model.ERole;
import com.eleftq.sec.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}