package com.poc.springsecurity.repository;

import com.poc.springsecurity.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    //since email is unique
    Optional<User> findByEmail(String email);
}
