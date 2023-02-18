package com.SpringSecurity.Service;

import com.SpringSecurity.models.Student;
import com.SpringSecurity.repository.StudentRepository;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;
import java.util.List;

@Service
@AllArgsConstructor
public class UserLoaderService implements UserDetailsService {

    @Autowired
    private StudentRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String userName;
        String password;
        List<GrantedAuthority> authorities;

        List<Student> users = this.userRepository.findByEmail(username);
        System.out.println("sdf");
        if(users.size() == 0)
            throw new UsernameNotFoundException("Email Not Found Exception");

        userName = users.get(0).getEmail();
        password = users.get(0).getPassword();
        authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(users.get(0).getRole()));


        return new User(userName, password, authorities);
    }
}
