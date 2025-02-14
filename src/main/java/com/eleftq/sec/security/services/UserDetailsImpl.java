package com.eleftq.sec.security.services;

import com.eleftq.sec.model.User;
import com.eleftq.sec.model.Permission;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class UserDetailsImpl implements UserDetails {
    private final String username;
    private final String password;
    private final String role;
    private final Set<String> permissions;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(String username, String password, String role, Set<String> permissions, Collection<? extends GrantedAuthority> authorities) {
        this.username = username;
        this.password = password;
        this.role = role;
        this.permissions = permissions;
        this.authorities = authorities;
    }

    public String getRole() {
        return role;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public static UserDetailsImpl build(User user) {
        // Get role name from your User entity.
        String roleName = String.valueOf(user.getRole().getName());

        // Ensure that the role authority has the proper "ROLE_" prefix.
        String roleAuthority = roleName.startsWith("ROLE_") ? roleName : "ROLE_" + roleName;

        // Convert permissions to a set of strings.
        Set<String> permissions = user.getRole().getPermissions().stream()
                .map(Permission::getName)
                .collect(Collectors.toSet());

        // Build the authorities list by first adding the role.
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(roleAuthority));

        // Then add all the permissions as authorities.
        authorities.addAll(
                permissions.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList())
        );

        // (Optional) Log the authorities for debugging
        System.out.println("User: " + user.getUsername() + " Authorities: " + authorities);

        return new UserDetailsImpl(
                user.getUsername(),
                user.getPassword(),
                roleName,
                permissions,
                authorities
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
