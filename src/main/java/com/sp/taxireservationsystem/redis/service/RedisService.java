package com.sp.taxireservationsystem.redis.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RedisService {

    private final RedisTemplate redisTemplate;

    public RedisService(RedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void setValues(String token, String name) {
        ValueOperations values = redisTemplate.opsForValue();
        values.set(token, name, Duration.ofMinutes(5));
    }
}
