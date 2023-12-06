package com.finalproject.bttd.dto;

import lombok.Data;

@Data
public class ApiResponse {
   public String msg;

    public static ApiResponse error(String s) {
      return new ApiResponse();
    }
}
