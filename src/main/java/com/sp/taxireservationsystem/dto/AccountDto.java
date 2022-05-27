package com.sp.taxireservationsystem.dto;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountDto {

    private String name;
    private String password;
    private String mail;

}
