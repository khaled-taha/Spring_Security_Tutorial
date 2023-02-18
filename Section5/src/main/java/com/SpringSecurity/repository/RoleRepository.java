package com.SpringSecurity.repository;

import com.SpringSecurity.models.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Authority, Long> {
    String findByUsername(String userName);
}
