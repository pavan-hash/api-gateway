package com.pk.api_gateway_v3.Configuration;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.rsocket.RSocketProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Set;


public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final String internalSecret;
    private final SecretKey secretkey;
    private static final Set<String> paths = Set.of("/AUTH-SERVER/auth/login");

    public JwtAuthFilter(@Value("${jwt.secret}") String secret,@Value("${gateway.internal-secret")String internalSecret)
    {
        this.secretkey= Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.internalSecret = internalSecret;
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        //allow login request to passthrough without any authorization
        if(request.getMethod()== HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        if(paths.contains(path)) {
            return chain.filter(exchange);
        }
        String header = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        //Check for every other request whether they have valid token
        if(header==null || !header.startsWith("Bearer ")) {
            return reject(exchange);
        }

        try
        {
            Jwts.parser().verifyWith(secretkey).build().
                    parseSignedClaims(header.substring(7));
        }
        catch(JwtException | IllegalArgumentException e)
        {
            return reject(exchange);
        }


        ServerHttpRequest secured = request.mutate().header("X-Gateway-Secret",internalSecret).build();

        return chain.filter(exchange.mutate().request(secured).build());
    }

    private Mono<Void> reject(ServerWebExchange exchange)
    {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();

    }
    @Override
    public int getOrder() {
        return -1;
    }
}
