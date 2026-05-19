package com.sincronia.idp_server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_REQUESTS_PER_WINDOW = 60;
    private static final long WINDOW_SECONDS = 60;

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        return !(
                path.startsWith("/auth/")
                        || path.startsWith("/oauth/login")
                        || path.startsWith("/oauth/totp")
                        || path.startsWith("/oauth/token")
                        || path.startsWith("/oauth/revoke")
                        || path.startsWith("/oauth/introspect")
        );
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String key = request.getRemoteAddr() + ":" + request.getRequestURI();
        long now = Instant.now().getEpochSecond();

        Bucket bucket = buckets.computeIfAbsent(key, ignored -> new Bucket(now, 0));

        synchronized (bucket) {
            if (now - bucket.windowStart >= WINDOW_SECONDS) {
                bucket.windowStart = now;
                bucket.count = 0;
            }

            bucket.count++;

            if (bucket.count > MAX_REQUESTS_PER_WINDOW) {
                response.setStatus(429);
                response.setContentType("application/json");
                response.getWriter().write("""
                        {"status":429,"error":"Too Many Requests","message":"Demasiadas solicitudes. Intente más tarde."}
                        """);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private static class Bucket {
        private long windowStart;
        private int count;

        private Bucket(long windowStart, int count) {
            this.windowStart = windowStart;
            this.count = count;
        }
    }
}