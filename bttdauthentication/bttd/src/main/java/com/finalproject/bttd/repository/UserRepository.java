package com.finalproject.bttd.repository;

import com.finalproject.bttd.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import java.util.ArrayList;
import java.util.Optional;

public interface UserRepository extends CrudRepository<User, Long> {
    @Override
    ArrayList<User> findAll();

    @Query("SELECT u FROM User u WHERE u.user_name = :user_name")
    Optional<User> findByuser_name(@Param("user_name") String user_name);


    //Boolean existByuser_name(String user_name);



}
