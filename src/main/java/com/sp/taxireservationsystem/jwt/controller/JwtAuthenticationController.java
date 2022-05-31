package com.sp.taxireservationsystem.jwt.controller;

import com.sp.taxireservationsystem.dto.AccountDto;
import com.sp.taxireservationsystem.entity.Account;
import com.sp.taxireservationsystem.jwt.config.JwtUtil;
import com.sp.taxireservationsystem.jwt.dto.JwtRequest;
import com.sp.taxireservationsystem.jwt.dto.JwtResponse;
import com.sp.taxireservationsystem.jwt.service.JwtUserDetailsService;
import com.sp.taxireservationsystem.redis.service.RedisService;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin
public class JwtAuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtTokenUtil;
    private final JwtUserDetailsService userDetailsService;
    private final RedisService redisService;

    public JwtAuthenticationController(AuthenticationManager authenticationManager,
                                       JwtUtil jwtTokenUtil,
                                       JwtUserDetailsService userDetailsService,
                                       RedisService redisService) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userDetailsService = userDetailsService;
        this.redisService = redisService;
    }

    @PostMapping(value = "/authenticate")
    public ResponseEntity<JwtResponse> createAuthenticationToken(@RequestBody JwtRequest jwtRequest) {
        authenticate(jwtRequest.getName(), jwtRequest.getPassword());
        final UserDetails userDetails = userDetailsService.loadUserByUsername(jwtRequest.getName());
        final String token = jwtTokenUtil.generateToken(userDetails);
        redisService.setValues(token, userDetails.getUsername());
        return ResponseEntity.ok(new JwtResponse(token));
    }

    @PostMapping(value = "/register")
    public ResponseEntity<Account> register(@RequestBody AccountDto accountDto) {
        return ResponseEntity.ok(userDetailsService.createAccount(accountDto));
    }

    @GetMapping(value = "refreshtoken")
    public ResponseEntity<?> refreshtoken(HttpServletRequest request) {
        DefaultClaims claims = (DefaultClaims) request.getAttribute("claims");
        Map<String, Object> expectedMap = getMapFromIoJsonwebtokenClaims(claims);
        String token = jwtTokenUtil.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());
        return ResponseEntity.ok(new JwtResponse(token));
    }

    private Map<String, Object> getMapFromIoJsonwebtokenClaims(DefaultClaims claims) {
        Map<String, Object> expectedMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            expectedMap.put(entry.getKey(), entry.getValue());
        }
        return expectedMap;
    }

    private void authenticate(String name, String password) throws DisabledException, BadCredentialsException {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(name, password));
        } catch (DisabledException e) {
            throw new DisabledException("Disabled", e);
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("INVALID CREDENTIAL", e);
        }
    }
}
