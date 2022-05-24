package com.sp.taxireservationsystem.jwtConfig;

import com.sp.taxireservationsystem.dto.AccountDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@CrossOrigin
public class JwtAuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @GetMapping(value = "/")
    public String success() {
        System.out.println("abaxcas");
        return "success";
    }

    @GetMapping(value = "/login")
    public String login() {
        //spring-boot-starter-thymeleaf 의존성을 사용하면 return login.html 파일로 리디렉션
        return "account/login";
    }

    @PostMapping(value = "/login")
    public void createAuthenticationToken(@ModelAttribute JwtRequest jwtRequest,
                                            HttpServletRequest request,
                                            HttpServletResponse response)
            throws DisabledException, BadCredentialsException, IOException {
        authenticate(jwtRequest.getUsername(), jwtRequest.getPassword());
        final UserDetails userDetails = userDetailsService.loadUserByUsername(jwtRequest.getUsername());
        response.setHeader("Authorization", "Bearer " + jwtTokenUtil.generateToken(userDetails));
        response.sendRedirect(request.getContextPath() + "/");
    }

    @GetMapping(value = "/register")
    public String register() {
        return "account/join";
    }

    @PostMapping(value = "/register")
    public String saveUser(@ModelAttribute AccountDto accountDto) {
        userDetailsService.save(accountDto);
        return "account/login";
    }

    @GetMapping(value = "/afterRequest")
    public String afterRequest() {
        return "afterRequest";
    }

    private void authenticate(String username, String password) throws DisabledException, BadCredentialsException {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new DisabledException("Disabled", e);
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("INVALID CREDENTIAL", e);
        }
    }
}
