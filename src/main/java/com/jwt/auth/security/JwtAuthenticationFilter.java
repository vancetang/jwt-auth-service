package com.jwt.auth.security;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * 自訂 JWT 身份驗證過濾器，用於攔截傳入的請求以驗證 JWT 權杖。
 * <p>
 * 如果在請求中找到有效的 JWT，此過濾器會在 Spring Security 的安全上下文中設定身份驗證資訊。
 * 此過濾器擴展了 {@link OncePerRequestFilter}，以確保每個請求只執行一次。
 * </p>
 */
@Component
@Slf4j // Lombok: 自動生成日誌記錄器
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    /**
     * 執行 JWT 身份驗證的核心過濾邏輯。
     * <p>
     * 此方法為每個請求呼叫，檢查 {@code Authorization} 標頭中是否存在 JWT。
     * 如果找到有效的權杖，則在 Spring Security 的上下文中對使用者進行身份驗證。
     * </p>
     * <p>
     * 處理流程：
     * <ol>
     * <li>從請求中提取 JWT ({@link #extractJwtFromRequest(HttpServletRequest)})。</li>
     * <li>如果 JWT 存在且通過 {@link JwtTokenProvider#validateToken(String)} 驗證：
     * <ul>
     * <li>從權杖中提取使用者 ID (通常是 subject) 和角色聲明。</li>
     * <li>將角色轉換為 {@link GrantedAuthority} 列表。</li>
     * <li>建立一個 {@link UsernamePasswordAuthenticationToken} (將使用者 ID 設為 principal，
     * 憑證設為 null，因為權杖已驗證)。</li>
     * <li>設定身份驗證物件的詳細資訊 (如 IP 位址、Session ID)。</li>
     * <li>將身份驗證物件設定到 {@link SecurityContextHolder} 中。</li>
     * </ul>
     * </li>
     * <li>如果 JWT 無效或不存在，則清除 {@link SecurityContextHolder} (以防萬一)，
     * 並允許請求繼續傳遞到過濾鏈中的下一個元素。後續的安全檢查將處理未認證的訪問。</li>
     * </ol>
     * </p>
     *
     * @param request     傳入的 {@link HttpServletRequest} 物件。
     * @param response    傳出的 {@link HttpServletResponse} 物件。
     * @param filterChain {@link FilterChain} 物件，用於將請求傳遞給鏈中的下一個過濾器。
     * @throws ServletException 如果發生 Servlet 特定錯誤。
     * @throws IOException      如果發生 I/O 錯誤。
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = extractJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
                String userId = jwtTokenProvider.getUserIdFromToken(jwt);
                Claims claims = jwtTokenProvider.getClaims(jwt);
                @SuppressWarnings("unchecked") // Suppress warning for casting roles
                List<String> roles = claims.get("roles", List.class);

                if (roles == null) {
                    log.warn(
                            "使用者 {} 的 JWT 權杖未包含 'roles' 聲明或型別錯誤，將視為無角色。",
                            userId);
                    roles = List.of(); // Default to no roles if claim is missing or incorrect type
                }

                List<GrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                // In a typical scenario with UserDetailsService, you might load UserDetails:
                // UserDetails userDetails = userDetailsService.loadUserByUsername(userId);
                // However, since our token is self-contained and already validated,
                // and we extract roles directly from it, we can construct the Authentication
                // token directly.
                // If additional checks from UserDetails (e.g., isAccountNonLocked) are needed,
                // then loading UserDetails would be more appropriate.
                // For this implementation, we directly use info from token.

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userId, // Principal can be userId string or UserDetails object
                        null, // Credentials are not needed as token is already validated
                        authorities);

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("成功從 JWT 驗證使用者 '{}'，角色為 {}。", userId, roles);

            } else {
                if (StringUtils.hasText(jwt)) {
                    log.debug("JWT 權杖存在但無效，請求路徑：{}。", request.getRequestURI());
                } else {
                    log.trace("在授權標頭中未找到 JWT 權杖，請求路徑：{}。", request.getRequestURI());
                }
            }
        } catch (JwtException e) {
            log.warn("處理 JWT 時發生錯誤，請求路徑：{}，錯誤訊息：{}", request.getRequestURI(), e.getMessage());
            // Allow the request to proceed without authentication.
            // Access to protected resources will be denied by subsequent security checks.
            SecurityContextHolder.clearContext(); // Ensure context is cleared on error
        } catch (Exception e) {
            log.error("JWT 驗證過濾器執行時發生未預期錯誤，請求路徑：{}，錯誤訊息：{}",
                    request.getRequestURI(), e.getMessage(), e);
            SecurityContextHolder.clearContext(); // Ensure context is cleared on error
        }

        filterChain.doFilter(request, response);
    }

    /**
     * 從請求的 "Authorization" 標頭中提取 JWT 權杖。
     * <p>
     * 預期的格式是 "Bearer &lt;token&gt;"。
     * </p>
     *
     * @param request {@link HttpServletRequest} 物件。
     * @return 如果找到且格式正確，則返回 JWT 權杖字串；否則返回 {@code null}。
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove "Bearer " prefix
        }
        log.trace("在授權標頭中未找到 'Bearer ' 權杖，請求路徑：{}。", request.getRequestURI());
        return null;
    }
}
