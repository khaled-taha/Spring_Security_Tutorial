package com.SpringSecurity.controller;


import com.SpringSecurity.Service.RegistrationService;
import com.SpringSecurity.models.Student;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/register")
@AllArgsConstructor
public class RegistrationController {

    @Autowired
    private RegistrationService registration;


    @PostMapping
    public ResponseEntity<String> register(@RequestBody Student student){
        return this.registration.register(student);
    }


}
