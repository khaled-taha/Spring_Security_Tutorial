package com.SpringSecurity.Service;


import com.SpringSecurity.models.Student;
import com.SpringSecurity.repository.StudentRepository;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import java.util.List;


@Service
@AllArgsConstructor
public class RegistrationService {

    @Autowired
    private StudentRepository userRepository;


    public ResponseEntity<String> register(Student user){
        List<Student> users = this.userRepository.findByEmail(user.getEmail());
        if(users.size() > 0)
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("This email is already used");

        this.userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body("User "+user.getName()+" created");
    }




}
