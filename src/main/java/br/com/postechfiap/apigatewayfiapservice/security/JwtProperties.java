package br.com.postechfiap.apigatewayfiapservice.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Classe para carregar propriedades relacionadas a JWT do application.yml.
 * Ajuda a centralizar e tipar as configurações.
 * Para produção, considere carregar de AWS Secrets Manager.
 */
@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {
    private String secret;
    // Poderia ter outras propriedades aqui, como validade do token para logs, etc.
}
