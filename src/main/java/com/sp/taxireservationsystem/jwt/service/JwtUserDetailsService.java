package com.sp.taxireservationsystem.jwt.service;

import com.sp.taxireservationsystem.dto.AccountDto;
import com.sp.taxireservationsystem.dto.Role;
import com.sp.taxireservationsystem.entity.Account;
import com.sp.taxireservationsystem.repository.AccountRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;

    public JwtUserDetailsService(AccountRepository accountRepository,
                                 PasswordEncoder passwordEncoder) {
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        Account account = accountRepository.findByName(name)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with username : " + name)
                );
        Set<Role> roles = account.getRoles();
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.name()));
        };
        return new User(account.getName(), account.getPassword(), authorities);
    }

    public Account createAccount(AccountDto accountDto) {
        Account account = new Account();
        account.setName(accountDto.getName());
        account.setMail(accountDto.getMail());
        account.setPassword(passwordEncoder.encode(accountDto.getPassword()));
        if (accountDto.getName().equals("admin")) {
            account.getRoles().add(Role.ADMIN);
        } else {
            account.getRoles().add(Role.USER);
        }
        accountRepository.save(account);
        return account;
    }
}
