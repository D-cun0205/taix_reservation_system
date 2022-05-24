package com.sp.taxireservationsystem.jwtConfig;

import com.sp.taxireservationsystem.dto.AccountDto;
import com.sp.taxireservationsystem.entity.Account;
import com.sp.taxireservationsystem.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private PasswordEncoder bcryptEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(username);
        if (account == null) {
            throw new UsernameNotFoundException("User not found with username : " + username);
        }
        return new User(account.getUsername(), account.getPassword(), new ArrayList<>());
    }

    public Account save(AccountDto accountDto) {
        Account account = new Account();
        account.setEmail(accountDto.getEmail());
        account.setPassword(bcryptEncoder.encode(accountDto.getPassword()));
        account.setUsername(accountDto.getUsername());
        return accountRepository.save(account);
    }
}
