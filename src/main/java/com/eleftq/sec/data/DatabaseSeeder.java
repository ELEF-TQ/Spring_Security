package com.eleftq.sec.data;

import com.eleftq.sec.model.*;
import com.eleftq.sec.repository.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class DatabaseSeeder implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DatabaseSeeder(RoleRepository roleRepository, PermissionRepository permissionRepository,
                          UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // Step 1: Create Permissions if they don't exist
        Permission readPermission = savePermissionIfNotExists("READ");
        Permission createPermission = savePermissionIfNotExists("CREATE");
        Permission updatePermission = savePermissionIfNotExists("UPDATE");
        Permission deletePermission = savePermissionIfNotExists("DELETE");

        // Step 2: Create Roles and assign permissions if they don't exist
        Set<Permission> adminPermissions = new HashSet<>(Arrays.asList(createPermission, readPermission, updatePermission, deletePermission));
        Role adminRole = saveRoleIfNotExists(ERole.ROLE_ADMIN, adminPermissions);

        Set<Permission> userPermissions = new HashSet<>(Collections.singletonList(readPermission));
        Role userRole = saveRoleIfNotExists(ERole.ROLE_USER, userPermissions);

        // Step 3: Create Superadmin User
        if (!userRepository.existsByUsername("superadmin")) {
            User superAdminUser = new User();
            superAdminUser.setUsername("superadmin");
            superAdminUser.setPassword(passwordEncoder.encode("superadminpassword"));
            superAdminUser.setRole(adminRole);
            userRepository.save(superAdminUser);
        }

        // Optionally, create a user with only the READ permission
        if (!userRepository.existsByUsername("normaluser")) {
            User normalUser = new User();
            normalUser.setUsername("normaluser");
            normalUser.setPassword(passwordEncoder.encode("normaluserpassword"));
            normalUser.setRole(userRole);
            userRepository.save(normalUser);
        }
    }

    private Permission savePermissionIfNotExists(String name) {
        return permissionRepository.findByName(name)
                .orElseGet(() -> permissionRepository.save(new Permission(name)));
    }

    private Role saveRoleIfNotExists(ERole roleName, Set<Permission> permissions) {
        return roleRepository.findByName(roleName)
                .orElseGet(() -> roleRepository.save(new Role(roleName, permissions)));
    }
}
