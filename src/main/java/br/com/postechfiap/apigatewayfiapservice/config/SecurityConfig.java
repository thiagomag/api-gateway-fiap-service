package br.com.postechfiap.apigatewayfiapservice.config;

import br.com.postechfiap.apigatewayfiapservice.security.ApiAuthenticationFilter;
import br.com.postechfiap.apigatewayfiapservice.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ApiAuthenticationFilter apiAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, ApiAuthenticationFilter apiAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.apiAuthenticationFilter = apiAuthenticationFilter;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        // Permite acesso a rotas públicas (login, registro, health checks, Swagger)
                        // Estas rotas não precisam de API Key nem JWT
                        .pathMatchers("/api/auth/login", "/api/auth/register", "/hello-gateway", "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**").permitAll()
                        // Permite acesso a rotas internas e do serviço de autenticação para que os filtros possam processá-las
                        // O ApiAuthenticationFilter e o JwtAuthenticationFilter decidirão a autenticação
                        .pathMatchers("/api/internal/**", "/api/auth/**").permitAll() // <-- Importante: permita para que os filtros customizados atuem
                        // Todas as outras requisições (não públicas e não tratadas pelos pathMatchers acima) exigem autenticação
                        .anyExchange().authenticated()
                )
                // Adiciona o filtro de API Key ANTES do filtro JWT
                // Ele tentará autenticar primeiro. Se conseguir, marcará a requisição.
                .addFilterAt(apiAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                // Adiciona o filtro JWT DEPOIS do filtro de API Key
                // Ele verificará se a requisição já foi autenticada por API Key antes de tentar validar o JWT.
                .addFilterAfter(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }
}