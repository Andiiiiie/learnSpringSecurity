package com.example.learnspringsecurity.security;


import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Data
public class Response<T> {
    private String status; // success, error, warning, info
    private String message;
    private String dataType;
    private T data;

    public Response(String status, String message, T data) {
        this.status = status;
        this.message = message;
        this.data = data;
    }

    public static <T> Response<T> send(HttpStatus statusCode, String status, String message, T data) {
        return new ResponseEntity<>(new Response<>(status, message, data), statusCode).getBody();
    }

    public static <T> Response<T> send(HttpStatus statusCode, String status,  T data) {
        return new ResponseEntity<>(new Response<>(status, null, data), statusCode).getBody();
    }

    public static <T> Response<?> send(HttpStatus statusCode, String status, String message) {
        return new ResponseEntity<>(new Response<>(status, message, null), statusCode).getBody();
    }


    public static <T> Response<?> notFound(String message) {
        return new ResponseEntity<>(new Response<>("error", message, null), HttpStatus.NOT_FOUND).getBody();
    }

    public static <T> Response<?> denied(String message) {
        return new ResponseEntity<>(new Response<>("error", message, null), HttpStatus.UNAUTHORIZED).getBody();
    }

    public String getDataType() {
        if (getData() != null)
            return getData().getClass().getSimpleName();
        return null;
    }


    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}