package com.jwt.auth.controller;

import com.jwt.auth.payload.request.LoginRequest;
import com.jwt.auth.payload.request.RefreshTokenRequest;
import com.jwt.auth.payload.response.JwtAuthenticationResponse;
import com.jwt.auth.payload.response.UserInfoResponse;
import com.jwt.auth.service.AuthService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

/**
 * REST 控制器，用於處理身份驗證相關的請求，例如登入、登出、刷新權杖，以及使用者資訊的檢索。
 * <p>
 * 所有端點都映射在 {@code /api/auth} 基本路徑下。
 * </p>
 */
@RestController
@RequestMapping("/api/auth") // API 基本路徑
@Slf4j // Lombok: 自動生成日誌記錄器
public class AuthController {

    private final AuthService authService;

    /**
     * 建構 {@code AuthController} 並注入所需的 {@link AuthService}。
     *
     * @param authService 負責處理身份驗證邏輯的服務。
     */
    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * 處理使用者登入請求。
     * <p>
     * 接收使用者名稱和密碼，成功驗證後返回 JWT 存取權杖 (Access Token) 和刷新權杖 (Refresh Token)。
     * </p>
     *
     * @param loginRequest 包含使用者名稱和密碼的 {@link LoginRequest} 物件。
     *                     請求本文 (Request Body) 中應包含 JSON 格式的登入資訊。
     * @return {@link ResponseEntity} 物件：
     *         <ul>
     *           <li>成功時 (HTTP 200 OK)：包含 {@link JwtAuthenticationResponse}，內含權杖資訊。</li>
     *           <li>若使用者名稱或密碼缺失 (HTTP 400 Bad Request)：包含錯誤訊息。</li>
     *           <li>若憑證無效 (HTTP 401 Unauthorized)：包含錯誤訊息。</li>
     *           <li>若發生其他內部錯誤 (HTTP 500 Internal Server Error)：包含錯誤訊息。</li>
     *         </ul>
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        if (loginRequest == null || loginRequest.getUsername() == null || loginRequest.getPassword() == null ||
            loginRequest.getUsername().isBlank() || loginRequest.getPassword().isBlank()) {
            log.warn("Login attempt with missing username or password.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username and password must be provided.");
        }

        log.info("Login attempt for user: {}", loginRequest.getUsername());
        try {
            JwtAuthenticationResponse jwtResponse = authService.loginUser(loginRequest);
            log.info("User {} logged in successfully.", loginRequest.getUsername());
            return ResponseEntity.ok(jwtResponse);
        } catch (BadCredentialsException e) {
            log.warn("Login failed for user {}: {}", loginRequest.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password.");
        } catch (Exception e) {
            log.error("An unexpected error occurred during login for user {}: {}", loginRequest.getUsername(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An internal error occurred. Please try again later.");
        }
    }

    // Logout endpoint will be added in a subsequent task.
    // Example (for future reference, assuming token is passed in Authorization header):
    // @PostMapping("/logout")
    // public ResponseEntity<?> logout(HttpServletRequest request) {
    //     String authHeader = request.getHeader("Authorization");
    //     if (authHeader != null && authHeader.startsWith("Bearer ")) {
    //         authService.logoutUser(authHeader);
    //         return ResponseEntity.ok("Logged out successfully.");
    //     }
    //     return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("No token provided or invalid token format.");
    // }

    /**
     * 處理使用者登出請求。
     * <p>
     * 使提供的 JWT Bearer 權杖失效 (透過 JTI 加入黑名單)。
     * </p>
     *
     * @param request {@link HttpServletRequest} 物件，應包含 {@code Authorization} 標頭，
     *                其值為 "Bearer {JWT_ACCESS_TOKEN}"。
     * @return {@link ResponseEntity} 物件：
     *         <ul>
     *           <li>成功登出時 (HTTP 200 OK)：包含成功訊息。</li>
     *           <li>若 {@code Authorization} 標頭缺失或格式不正確 (HTTP 400 Bad Request)：包含錯誤訊息。</li>
     *           <li>若提供的權杖無效 (例如已過期或簽名錯誤) (HTTP 400 Bad Request)：包含權杖無效的訊息。</li>
     *           <li>若發生其他內部錯誤 (HTTP 500 Internal Server Error)：包含錯誤訊息。</li>
     *         </ul>
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                authService.logoutUser(token); // Pass only the token string
                log.info("User successfully logged out. Token invalidated.");
                return ResponseEntity.ok("Successfully logged out.");
            } catch (JwtException e) {
                log.warn("Logout failed: Invalid token provided. Reason: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid token: " + e.getMessage());
            } catch (Exception e) {
                log.error("An unexpected error occurred during logout: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An internal error occurred during logout.");
            }
        }
        log.warn("Logout attempt with missing or invalid Bearer token.");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Authorization header with Bearer token is required.");
    }

    /**
     * 處理使用刷新權杖 (Refresh Token) 來更新存取權杖 (Access Token) 的請求。
     *
     * @param refreshTokenRequest 包含刷新權杖的 {@link RefreshTokenRequest} 物件。
     *                            請求本文 (Request Body) 中應包含 JSON 格式的刷新權杖資訊。
     * @return {@link ResponseEntity} 物件：
     *         <ul>
     *           <li>成功時 (HTTP 200 OK)：包含新的 {@link JwtAuthenticationResponse} (內含新的存取權杖)。</li>
     *           <li>若刷新權杖缺失 (HTTP 400 Bad Request)：包含錯誤訊息。</li>
     *           <li>若刷新權杖無效或已過期 (HTTP 401 Unauthorized)：包含錯誤訊息。</li>
     *           <li>若請求資料有誤 (HTTP 400 Bad Request)：包含錯誤訊息。</li>
     *           <li>若發生其他內部錯誤 (HTTP 500 Internal Server Error)：包含錯誤訊息。</li>
     *         </ul>
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        if (refreshTokenRequest == null || refreshTokenRequest.getRefreshToken() == null || refreshTokenRequest.getRefreshToken().isBlank()) {
            log.warn("Refresh token request with missing token.");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Refresh token must be provided.");
        }

        String requestRefreshToken = refreshTokenRequest.getRefreshToken();
        log.info("Attempting to refresh access token using refresh token (ending with ...{})",
                 requestRefreshToken.length() > 7 ? requestRefreshToken.substring(requestRefreshToken.length() - 7) : requestRefreshToken);

        try {
            JwtAuthenticationResponse newTokens = authService.refreshAccessToken(requestRefreshToken);
            log.info("Access token refreshed successfully for refresh token (ending with ...{})",
                     requestRefreshToken.length() > 7 ? requestRefreshToken.substring(requestRefreshToken.length() - 7) : requestRefreshToken);
            return ResponseEntity.ok(newTokens);
        } catch (JwtException e) {
            log.warn("Refresh token failed: {}. Refresh token (ending with ...{})", e.getMessage(),
                     requestRefreshToken.length() > 7 ? requestRefreshToken.substring(requestRefreshToken.length() - 7) : requestRefreshToken);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired refresh token: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("Refresh token failed due to illegal argument: {}. Refresh token (ending with ...{})", e.getMessage(),
                                 requestRefreshToken.length() > 7 ? requestRefreshToken.substring(requestRefreshToken.length() - 7) : requestRefreshToken);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid refresh token data: " + e.getMessage());
        } catch (Exception e) {
            log.error("An unexpected error occurred during token refresh for refresh token (ending with ...{}): {}",
                      requestRefreshToken.length() > 7 ? requestRefreshToken.substring(requestRefreshToken.length() - 7) : requestRefreshToken, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An internal error occurred during token refresh.");
        }
    }

    /**
     * 檢索當前已認證使用者的資訊。
     * <p>
     * 此端點受到保護，需要有效的 JWT 進行認證。
     * 使用者資訊是從 Spring Security 的 {@link SecurityContextHolder} 中獲取的 {@link Authentication} 物件中提取的。
     * </p>
     *
     * @return {@link ResponseEntity} 物件：
     *         <ul>
     *           <li>成功時 (HTTP 200 OK)：包含 {@link UserInfoResponse}，內含使用者 ID 和角色等資訊。</li>
     *           <li>若使用者未通過認證 (HTTP 401 Unauthorized)：包含錯誤訊息。</li>
     *         </ul>
     */
    @GetMapping("/user/info")
    @PreAuthorize("isAuthenticated()") // 確保使用者已通過認證才能存取此端點
    public ResponseEntity<?> getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            log.warn("Attempt to access /user/info without proper authentication.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
        }

        String userId = authentication.getName(); // For UsernamePasswordAuthenticationToken, getName() returns the principal's name (our userId)

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.info("User info retrieved for userId: '{}' with roles: {}", userId, roles);

        UserInfoResponse userInfoResponse = new UserInfoResponse(
                userId,
                roles,
                "User information retrieved successfully."
        );

        return ResponseEntity.ok(userInfoResponse);
    }
}
