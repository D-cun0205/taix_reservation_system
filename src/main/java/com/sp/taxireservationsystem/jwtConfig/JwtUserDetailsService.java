package com.sp.taxireservationsystem.jwtConfig;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class JwtUserDetailsService implements UserDetailsService {

//    @Autowired
//    private AccountRepository accountRepository;

//    @Autowired
//    private PasswordEncoder bcryptEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if ("javainuse".equals(username)) {
            return new User(
                    "javainuse",
                    "$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6",
                    new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found with username : " + username);
        }
    }

//    public Account save(AccountDto accountDto) {
//        Account account = new Account();
//        account.setEmail(accountDto.getEmail());
//        account.setPassword(bcryptEncoder.encode(accountDto.getPassword()));
//        account.setUsername(accountDto.getUsername());
//        return accountRepository.save(account);
//    }
}
