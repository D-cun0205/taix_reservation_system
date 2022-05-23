package com.sp.taxireservationsystem.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AccountDto {

    private String email;
    private String password;
    private String username;
}
