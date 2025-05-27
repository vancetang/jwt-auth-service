package com.jwt.auth.service;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import com.jwt.auth.payload.request.LoginRequest;
import com.jwt.auth.payload.response.JwtAuthenticationResponse;
import com.jwt.auth.security.JwtTokenProvider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;

/**
 * 處理身份驗證相關核心邏輯的服務類別，例如使用者登入、登出及權杖刷新。
 * <p>
 * 此服務依賴 {@link JwtTokenProvider} 來生成和驗證 JWT。
 * </p>
 */
@Service
@Slf4j // Lombok: 自動生成日誌記錄器
public class AuthService {
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    /**
     * 根據提供的登入請求對使用者進行身份驗證。
     * <p>
     * **注意：** 目前此實作中的使用者憑證是硬編碼的 (hardcoded)。
     * 在實際應用中，應替換為與資料庫或其他身份存儲進行驗證的邏輯，
     * 並整合 Spring Security 的 {@code AuthenticationManager} 和
     * {@code UserDetailsService}。
     * </p>
     * <p>
     * 硬編碼的使用者：
     * <ul>
     * <li>使用者名稱 "user", 密碼 "password" -> 角色 "ROLE_USER"</li>
     * <li>使用者名稱 "admin", 密碼 "adminpass" -> 角色 "ROLE_ADMIN", "ROLE_USER"</li>
     * </ul>
     * </p>
     *
     * @param loginRequest 包含使用者名稱和密碼的 {@link LoginRequest} 物件。
     * @return 成功驗證後，返回包含存取權杖和刷新權杖的 {@link JwtAuthenticationResponse} 物件。
     * @throws BadCredentialsException 如果提供的憑證無效。
     */
    public JwtAuthenticationResponse loginUser(LoginRequest loginRequest) {
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        // --- Hardcoded User Authentication ---
        // In a real application, this would involve checking credentials against a
        // database
        // and using Spring Security's AuthenticationManager and UserDetailsService.
        List<String> roles;
        if ("user".equals(username) && "password".equals(password)) {
            roles = Collections.singletonList("ROLE_USER");
            log.info("使用者 '{}' 驗證成功，角色為 ROLE_USER。", username);
        } else if ("admin".equals(username) && "adminpass".equals(password)) {
            roles = Arrays.asList("ROLE_ADMIN", "ROLE_USER");
            log.info("使用者 '{}' 驗證成功，角色為 ROLE_ADMIN, ROLE_USER。", username);
        } else {
            log.warn("使用者 '{}' 驗證失敗：憑證無效。", username);
            throw new BadCredentialsException("Invalid username or password");
        }
        // --- End Hardcoded User Authentication ---

        // 1. 產生 Refresh Token 並獲取其 JTI
        String refreshToken = jwtTokenProvider.generateRefreshToken(username);
        String refreshTokenJti = jwtTokenProvider.getJtiFromToken(refreshToken); // 假設 getJtiFromToken 能正確解析剛生成的 token

        // 2. 產生 Access Token，並將 Refresh Token JTI 傳入
        String accessToken = jwtTokenProvider.generateAccessToken(username, roles, refreshTokenJti);

        log.debug("已為 {} 產生 Access Token：{}", username, accessToken);
        log.debug("已為 {} 產生 Refresh Token：{}", username, refreshToken);
        log.info("使用者 {} 已登入。AccessToken JTI 已關聯至 RefreshToken JTI：{}", username, refreshTokenJti);

        return new JwtAuthenticationResponse(accessToken, refreshToken);
    }

    /**
     * 登出使用者，使其當前的 JWT 權杖失效。
     * <p>
     * 此操作會使傳入的 Access Token 及其關聯的 Refresh Token (如果 `rt_jti` Claim 存在於 Access Token
     * 中)
     * 的 JTI 都被加入黑名單。
     * </p>
     * <p>
     * 此方法依賴於 {@link JwtTokenProvider} 中實現的基於 JTI (JWT ID) 的失效機制。
     * 它會嘗試從傳入的 token 字串 (應為 Access Token) 中提取 JTI，並將其加入黑名單。
     * </p>
     * <p>
     * 注意：此方法目前僅使提供的存取權杖失效。根據具體的安全策略，
     * 可能還需要考慮刷新權杖的失效機制。
     * </p>
     *
     * @param token 要使其失效的 JWT 權杖字串 (通常是存取權杖)。
     *              期望的格式為 "Bearer {JWT_TOKEN}"，但此方法內部會處理 "Bearer " 前綴。
     *              如果傳入的是已移除 "Bearer " 前綴的純 token，也能正確處理。
     */
    public void logoutUser(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            String actualToken = token.substring(7); // Remove "Bearer " prefix
            log.info("嘗試使權杖於登出時失效。");
            jwtTokenProvider.invalidateToken(actualToken);
            // Note: Refresh token invalidation might also be needed depending on the
            // strategy.
            // For now, only the provided token (assumed Access Token) is invalidated.
        } else {
            log.warn("登出嘗試時 Bearer 權杖無效或缺失。");
        }
    }

    /**
     * 使用有效的刷新權杖 (Refresh Token) 來獲取一個新的存取權杖 (Access Token)。
     * <p>
     * 流程如下：
     * <ol>
     * <li>檢查傳入的刷新權杖是否為空。</li>
     * <li>使用 {@link JwtTokenProvider#validateToken(String)} 驗證刷新權杖的有效性
     * (簽名、未過期、未被吊銷)。</li>
     * <li>從刷新權杖中提取 "typ" (類型) 聲明，並驗證其是否為 "Refresh"。</li>
     * <li>提取使用者 ID (subject)。</li>
     * <li>根據使用者 ID 獲取使用者角色 (目前為硬編碼，實際應用中應從資料庫查詢)。</li>
     * <li>使用 {@link JwtTokenProvider#generateAccessToken(String, List)}
     * 生成一個新的存取權杖。</li>
     * <li>返回包含新存取權杖和原始刷新權杖的 {@link JwtAuthenticationResponse}。</li>
     * </ol>
     * </p>
     * <p>
     * **安全性考量：** 目前的實作在刷新後返回原始的刷新權杖。
     * 為了增強安全性，可以考慮實作刷新權杖輪換 (Refresh Token Rotation) 策略，
     * 即在發放新存取權杖的同時，也發放一個新的刷新權杖，並使舊的刷新權杖失效。
     * (相關邏輯已在程式碼中以註解方式標出)。
     * </p>
     *
     * @param requestRefreshToken 客戶端提供的刷新權杖字串。
     * @return 包含新的存取權杖和原始 (或新的，如果實現了輪換) 刷新權杖的 {@link JwtAuthenticationResponse}。
     * @throws io.jsonwebtoken.JwtException 如果刷新權杖無效、已過期、格式錯誤，或類型不正確。
     * @throws IllegalArgumentException     如果刷新權杖字串為 {@code null} 或空白。
     */
    public JwtAuthenticationResponse refreshAccessToken(String requestRefreshToken) {
        if (requestRefreshToken == null || requestRefreshToken.isBlank()) {
            throw new IllegalArgumentException("Refresh token cannot be null or blank.");
        }

        // 1. 驗證傳入的 Refresh Token
        if (!jwtTokenProvider.validateToken(requestRefreshToken)) {
            log.warn("刷新權杖驗證失敗。Token: ...{}",
                    requestRefreshToken.length() > 7 ? requestRefreshToken.substring(requestRefreshToken.length() - 7)
                            : requestRefreshToken);
            throw new JwtException("Invalid or expired refresh token.");
        }

        Claims refreshTokenClaims = jwtTokenProvider.getClaims(requestRefreshToken);
        String tokenType = refreshTokenClaims.get("typ", String.class);
        if (!"Refresh".equals(tokenType)) {
            log.warn("刷新時權杖型別無效。預期為 'Refresh'，實際為 '{}'。Token: ...{}", tokenType,
                    requestRefreshToken.length() > 7 ? requestRefreshToken.substring(requestRefreshToken.length() - 7)
                            : requestRefreshToken);
            throw new JwtException("Invalid token type. Expected a refresh token.");
        }

        String userId = refreshTokenClaims.getSubject();
        String oldRefreshTokenJti = refreshTokenClaims.getId();
        Date oldRefreshTokenExpiry = refreshTokenClaims.getExpiration();

        // 2. 提取角色 (與登入邏輯類似，實際應從DB獲取)
        List<String> roles;
        if ("user".equals(userId)) {
            roles = Collections.singletonList("ROLE_USER");
        } else if ("admin".equals(userId)) {
            roles = Arrays.asList("ROLE_ADMIN", "ROLE_USER");
        } else {
            log.warn(
                    "無法從刷新權杖判斷使用者 ID '{}' 的角色，將不賦予新存取權杖任何角色。", userId);
            roles = Collections.emptyList();
        }

        // 3. Refresh Token 輪換：產生新的 Refresh Token
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(userId);
        String newRefreshTokenJti = jwtTokenProvider.getJtiFromToken(newRefreshToken); // 獲取新 RT 的 JTI

        // 4. 產生新的 Access Token，關聯到新的 Refresh Token JTI
        String newAccessToken = jwtTokenProvider.generateAccessToken(userId, roles, newRefreshTokenJti);

        // 5. 使舊的 Refresh Token 失效
        // 使用 invalidateJti 方法，傳入 JTI 和其原始過期時間
        if (oldRefreshTokenJti != null && oldRefreshTokenExpiry != null) {
            jwtTokenProvider.invalidateJti(oldRefreshTokenJti, oldRefreshTokenExpiry.getTime());
            log.info("舊的 Refresh Token JTI {} 已於權杖刷新時失效。", oldRefreshTokenJti);
        } else {
            // 如果無法獲取 JTI 或過期時間 (理論上不應發生，因為前面已成功解析 claims)
            // 也可以嘗試直接用 token 字串使之失效，但 invalidateJti 更精確
            jwtTokenProvider.invalidateToken(requestRefreshToken);
            log.warn(
                    "舊的 Refresh Token (JTI: {}) 因 claims 缺少 JTI/過期時間，已直接以完整權杖字串失效。", oldRefreshTokenJti);
        }

        log.info("已為使用者 '{}' 刷新 Access Token，新 AT 已關聯至新 RT JTI {}，舊 RT JTI {} 已失效。",
                userId, newRefreshTokenJti, oldRefreshTokenJti);

        return new JwtAuthenticationResponse(newAccessToken, newRefreshToken);
    }
}
