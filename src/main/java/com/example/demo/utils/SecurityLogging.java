package com.example.demo.utils;

import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityLogging {
    public static void log(String message){
        System.out.println(message);
        System.out.println(Thread.currentThread().getName());
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        System.out.println();
    }
}
