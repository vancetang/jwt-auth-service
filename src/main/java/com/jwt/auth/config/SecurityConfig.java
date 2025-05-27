package com.jwt.auth.config;

import com.jwt.auth.security.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security 組態類別。
 * <p>
 * 此類別負責設定應用程式的安全策略，包括：
 * <ul>
 *     <li>JWT 認證過濾器 ({@link JwtAuthenticationFilter}) 的整合</li>
 *     <li>CSRF (跨站請求偽造) 保護的禁用 (適用於無狀態 API)</li>
 *     <li>Session 管理策略 (設定為無狀態)</li>
 *     <li>請求授權規則 (定義公開端點與受保護端點)</li>
 *     <li>啟用方法級別的安全性控制 (如 {@code @PreAuthorize})</li>
 * </ul>
 * </p>
 */
@Configuration
@EnableWebSecurity // 啟用 Spring Security 的 Web 安全性支援
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true) // 啟用方法級別的安全性註解
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * 建構 {@code SecurityConfig} 並注入 {@link JwtAuthenticationFilter}。
     *
     * @param jwtAuthenticationFilter 用於處理 JWT 權杖的過濾器。
     */
    @Autowired
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    /**
     * 設定並配置安全過濾鏈 ({@link SecurityFilterChain})。
     * <p>
     * 此過濾鏈將應用於所有傳入的 HTTP 請求，定義了核心的安全行為。
     * 主要設定包括：
     * <ul>
     *   <li>**CSRF 保護**：禁用，因為 JWT 通常用於無狀態 API，客戶端不依賴 Cookie session。</li>
     *   <li>**Session 管理**：設定為 {@link SessionCreationPolicy#STATELESS STATELESS}，
     *       因為每個請求都應透過 JWT 獨立認證，不依賴伺服器端 Session。</li>
     *   <li>**請求授權 (Authorization)**：
     *     <ul>
     *       <li>{@code /api/auth/**} (如登入、註冊、刷新權杖等端點) 設定為公開存取 (permitAll)。</li>
     *       <li>{@code /public/**} (範例公開目錄) 設定為公開存取。</li>
     *       <li>根路徑 {@code /}, 錯誤頁面 {@code /error}, {@code /favicon.ico}, Swagger UI 相關路徑
     *           ({@code /swagger-ui/**}, {@code /v3/api-docs/**}) 設定為公開存取。</li>
     *       <li>所有其他未明確指定的請求 ({@code anyRequest()}) 都需要經過認證 ({@code authenticated()})。</li>
     *     </ul>
     *   </li>
     *   <li>**JWT 過濾器整合**：將自訂的 {@link JwtAuthenticationFilter} 添加到過濾器鏈中，
     *       置於 {@link UsernamePasswordAuthenticationFilter} 之前，以處理請求中的 JWT。</li>
     * </ul>
     * </p>
     *
     * @param http {@link HttpSecurity} 物件，用於建構安全過濾鏈的配置。
     * @return 設定完成的 {@link SecurityFilterChain}。
     * @throws Exception 如果在組態過程中發生錯誤。
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Disable CSRF protection (common for stateless REST APIs)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Use stateless sessions
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/auth/**").permitAll() // Allow public access to /api/auth/ (login, refresh, logout etc.)
                .requestMatchers("/public/**").permitAll() // Example: Allow public access to a /public/ directory
                .requestMatchers("/", "/error", "/favicon.ico", "/swagger-ui/**", "/v3/api-docs/**").permitAll() // Allow Swagger and basic pages
                .anyRequest().authenticated() // All other requests must be authenticated
            );

        // Add our custom JWT authentication filter before the standard UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Note: UserDetailsService bean is already provided by CustomUserDetailsService,
    // and PasswordEncoder is not strictly needed for JWT validation itself if not using form-based login
    // with password checking via AuthenticationManager.
    // If an AuthenticationManager is needed for other purposes, it can be exposed as a Bean.

    // Optional: If you need a PasswordEncoder bean (e.g., for UserDetailsService if you were using it)
    // @Bean
    // public PasswordEncoder passwordEncoder() {
    //     return new BCryptPasswordEncoder();
    // }

    // Optional: If you need to expose AuthenticationManager as a bean
    // (e.g., if not using HttpSecurity.getSharedObject(AuthenticationManagerBuilder.class))
    // @Bean
    // public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    //    return authenticationConfiguration.getAuthenticationManager();
    // }
}
