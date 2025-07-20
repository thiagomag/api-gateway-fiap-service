package br.com.postechfiap.apigatewayfiapservice.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

@Component
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = BEARER_PREFIX.length();

    private final SecretKey jwtSecretKey;

    public JwtAuthenticationFilter(JwtProperties jwtProperties) {
        this.jwtSecretKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        Boolean authenticatedByApiKey = exchange.getAttribute(ApiAuthenticationFilter.API_KEY_AUTHENTICATED_ATTRIBUTE);
        if (Boolean.TRUE.equals(authenticatedByApiKey)) {
            log.debug("Requisição para {} já autenticada por API Key. Pulando validação JWT.", path);
            return chain.filter(exchange);
        }

        if (isPublicRoute(path, request)) {
            log.debug("Rota pública: {}. Pulando validação JWT.", path);
            return chain.filter(exchange);
        }

        String authorizationHeader = request.getHeaders().getFirst(AUTHORIZATION_HEADER);

        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            log.warn("Token JWT ausente ou mal formatado para rota protegida: {}", path);
            return onError(exchange, "JWT Token is missing or malformed.", HttpStatus.UNAUTHORIZED);
        }

        String token = authorizationHeader.substring(BEARER_PREFIX_LENGTH);

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(jwtSecretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String userId = claims.getSubject();
            List<String> roles = extractRoles(claims);

            log.debug("JWT valido para o User ID: '{}', Roles: '{}' no caminho: {}", userId, String.join(",", roles), path);

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Id", userId)
                    .header("X-User-Roles", String.join(",", roles))
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (SignatureException e) {
            log.warn("Falha na validação da assinatura JWT para o caminho '{}'. Token: {}. Erro: {}", path, truncateToken(token), e.getMessage());
            return onError(exchange, "Assinatura JWT inválida. Autenticação falhou.", HttpStatus.UNAUTHORIZED);
        } catch (MalformedJwtException e) {
            log.warn("JWT malformado para o caminho '{}'. Token: {}. Erro: {}", path, truncateToken(token), e.getMessage());
            return onError(exchange, "JWT malformado. Autenticação falhou. Verifique o formato do token.", HttpStatus.BAD_REQUEST);
        } catch (ExpiredJwtException e) {
            log.warn("JWT expirado para o caminho '{}'. Usuário: {}. Erro: {}", path, e.getClaims().getSubject(), e.getMessage());
            return onError(exchange, "O JWT expirou. Por favor, faça login novamente.", HttpStatus.UNAUTHORIZED);
        } catch (UnsupportedJwtException e) {
            log.warn("JWT não suportado para o caminho '{}'. Token: {}. Erro: {}", path, truncateToken(token), e.getMessage());
            return onError(exchange, "Formato de JWT não suportado.", HttpStatus.UNAUTHORIZED);
        } catch (IllegalArgumentException e) {
            log.warn("Argumento inválido para JWT (ex: token vazio/nulo) para o caminho '{}'. Erro: {}", path, e.getMessage());
            return onError(exchange, "JWT é inválido ou ausente.", HttpStatus.BAD_REQUEST);
        } catch (JwtException e) { // Captura qualquer outra JwtException
            log.error("Erro genérico no JWT para o caminho '{}'. Token: {}. Erro: {}", path, truncateToken(token), e.getMessage(), e);
            return onError(exchange, "Token JWT inválido. Autenticação falhou.", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) { // Captura qualquer outra exceção inesperada
            log.error("Erro inesperado no filtro JWT para o caminho '{}'. Erro: {}", path, e.getMessage(), e);
            return onError(exchange, "Ocorreu um erro inesperado durante a autenticação.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorJson = String.format(
                "{\"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"timestamp\": \"%s\"}",
                httpStatus.value(), httpStatus.getReasonPhrase(), errorMessage, java.time.Instant.now().toString()
        );

        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorJson.getBytes(StandardCharsets.UTF_8))));
    }


    private boolean isPublicRoute(String path, ServerHttpRequest request) {

        if ((path.startsWith("/api/auth/users") || path.startsWith("/api/auth/users/login") ) && request.getMethod().matches("POST")) {
            return true;
        }
        return path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui") || path.startsWith("/api/swagger-ui.html");
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Claims claims) {

        String rolesString = claims.get("roles", String.class);
        if (rolesString != null && !rolesString.isEmpty()) {
            return List.of(rolesString.split(","));
        }

        List<String> roles = claims.get("roles", List.class);
        if (roles != null) {
            return roles;
        }

        return Collections.emptyList();
    }

    private String truncateToken(String token) {
        if (token == null || token.length() <= 50) {
            return token;
        }
        return token.substring(0, 50) + "...";
    }
}