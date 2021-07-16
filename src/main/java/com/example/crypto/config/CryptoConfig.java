package com.example.crypto.config;

import com.example.crypto.CryptoServiceImpl;
import com.example.crypto.properties.PgpProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptoConfig {
    @Autowired
    PgpProperty pgpProperty;
    @Bean
    public CryptoServiceImpl cryptoServiceInjection(){
        return new CryptoServiceImpl(pgpProperty);
    }
}
