package com.example.demo.form;

import org.hamcrest.CoreMatchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SignupControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    public void sigupFormTest() throws Exception{
        mockMvc.perform(get("/signup"))
                .andExpect(content().string(containsString("_csrf")))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    public void sigupProcessTest() throws Exception {
        mockMvc.perform(post("/signup")
                .param("username", "andrew")
                .param("password", "123")
                // csrf 추가
                .with(csrf())
        ).andDo(print())
                .andExpect(status().is3xxRedirection());

    }
}