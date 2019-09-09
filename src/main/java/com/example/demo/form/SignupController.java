package com.example.demo.form;

import com.example.demo.account.Account;
import com.example.demo.account.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/signup")
public class SignupController {

    @Autowired
    AccountService accountService;

    @GetMapping
    public String signup(Model model){
        model.addAttribute("account", new Account());
        return "signup";
    }

    @PostMapping
    public String processingSignup(@ModelAttribute Account account){
        account.setRole("USER");
        accountService.createAccount(account);
        return "redirect:/";
    }
}
