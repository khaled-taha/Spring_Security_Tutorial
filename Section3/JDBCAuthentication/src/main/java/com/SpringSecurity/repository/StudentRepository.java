package com.SpringSecurity.repository;

import com.SpringSecurity.models.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface StudentRepository extends JpaRepository<Student, Long> {

    List<Student> findByEmail(String email);
}
