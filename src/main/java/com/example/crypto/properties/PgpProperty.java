package com.example.crypto.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix ="pgp")
@Data
public class PgpProperty {
    private String resourcePath;
    private String passphrase;
}
