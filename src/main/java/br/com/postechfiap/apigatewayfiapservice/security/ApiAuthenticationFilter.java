package br.com.postechfiap.apigatewayfiapservice.security;

import lombok.RequiredArgsConstructor;
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

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class ApiAuthenticationFilter implements WebFilter {

    private static final String API_KEY_HEADER = "X-API-Key";
    public static final String API_KEY_AUTHENTICATED_ATTRIBUTE = "api_key_authenticated"; // Atributo para marcar a requisição

    private final ApiKeysProperties apiKeysProperties;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Define quais rotas podem ser autenticadas por API Key
        boolean isInternalPath = path.startsWith("/api/internal/");
        boolean isAuthServicePath = path.startsWith("/api/auth/"); // Adicionado para o auth_service

        // Se não for uma rota interna NEM uma rota do serviço de autenticação,
        // simplesmente passa para o próximo filtro (provavelmente o JWT Filter)
        if (!isInternalPath && !isAuthServicePath) {
            return chain.filter(exchange);
        }

        // Tenta obter a API Key do cabeçalho
        Optional<String> apiKeyHeader = Optional.ofNullable(request.getHeaders().getFirst(API_KEY_HEADER));

        if (apiKeyHeader.isEmpty()) {
            // Se for uma rota que *poderia* usar API Key, mas a chave está ausente,
            // e não é uma rota de login/registro (que são públicas e não precisam de API Key)
            // Permite que o próximo filtro (JWT) lide com isso, a menos que seja uma rota interna *exclusiva* de API Key.
            // Para /api/auth/**, se a API Key estiver ausente, o JWT Filter deve tentar autenticar.
            // Para /api/internal/**, se a API Key estiver ausente, deve falhar aqui.
            if (isInternalPath) { // Rotas internas SÓ podem ser acessadas com API Key
                log.warn("Tentativa de acesso a rota interna protegida sem API Key: {}", path);
                return onError(exchange, "API Key is missing for internal access.", HttpStatus.UNAUTHORIZED);
            }
            // Para /api/auth/**, se não tiver API Key, deixa o JWT Filter tentar.
            return chain.filter(exchange);
        }

        String providedApiKey = apiKeyHeader.get();

        if (apiKeysProperties.getValidApiKeys().contains(providedApiKey)) {
            log.debug("API Key válida para rota: {}", path);
            // Marca a requisição como autenticada por API Key
            exchange.getAttributes().put(API_KEY_AUTHENTICATED_ATTRIBUTE, true);
            return chain.filter(exchange); // Prossegue com a requisição
        } else {
            log.warn("API Key inválida para rota: {}. Chave fornecida: {}", path, providedApiKey);
            return onError(exchange, "Invalid API Key.", HttpStatus.UNAUTHORIZED);
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
}