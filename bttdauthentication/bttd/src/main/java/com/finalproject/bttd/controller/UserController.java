package com.finalproject.bttd.controller;

import com.finalproject.bttd.apiresponse.ApiResponse;
import com.finalproject.bttd.dto.UserDto;
import com.finalproject.bttd.entity.User;
import com.finalproject.bttd.repository.UserRepository;
import com.finalproject.bttd.service.UserService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Controller
public class UserController {
    @Autowired
   private UserRepository userRepository;
   private UserService userService;
    private BindingResult bindingResult;


    @PostMapping("/user/adduser")
    @ResponseBody
        public ResponseEntity<String> createUser(@RequestBody UserDto userDto) {
            try {

                User user = userDto.toEntity();
                  User saved1 = userRepository.save(user);
                //    ApiResult<User> utils = ApiUtils.success(saved);
                //    Map<String, Object> responseData = new HashMap<>();
                //    responseData.put("success", true);
                //    utils.setData(responseData);
                System.out.println(saved1);
                return new ResponseEntity<>("{\"data\":{\"success\":true}}", HttpStatus.OK);
            } catch (Exception e) {
                // 예외 처리 또는 로깅을 수행할 수 있음
//            ApiResult<User> errorUtils = (ApiResult<User>) ApiUtils.error("erro");
                //    ApiResponse<?> response = ApiResponse.createFail(bindingResult);
                return new ResponseEntity<>("{\"success\":\"catcherror\"}", HttpStatus.BAD_REQUEST);
            }
        }


        @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        // 예외 처리 또는 로깅을 수행할 수 있습니다.

        // 항상 {"success": "fail"}를 반환합니다.
        return new ResponseEntity<>("{\"success\":\"fail\"}", HttpStatus.INTERNAL_SERVER_ERROR);
    }

//
}
