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
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;


public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final SecretKey secretkey;

    public JwtAuthFilter(@Value("${jwt.secret}") String secret)
    {
        this.secretkey= Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpRequest request = exchange.getRequest();
        //allow login request to passthrough without any authorization
        if(request.getURI().getPath().startsWith("/AUTH-SERVER/")
        || request.getMethod()== HttpMethod.OPTIONS) {
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

        return chain.filter(exchange);
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
