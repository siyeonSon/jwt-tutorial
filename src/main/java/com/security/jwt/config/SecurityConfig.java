package com.security.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    // h2 database 테스트가 원활하도록 관련 API 들은 전부 무시
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers("/h2-console/**", "/favicon.ico");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()  // 권한요청 처리 설정 메서드
                .requestMatchers("/api/hello").permitAll()  // 접속 허용
                .anyRequest().authenticated()
            .and()
                .headers().frameOptions().disable()  // X-Frame-Options in Spring Security 중지
            .and()
                .csrf()  // CSRF 중지
                .ignoringRequestMatchers("/h2-console/**")
                .disable();
        return http.build();
    }
}