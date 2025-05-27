package com.jwt.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

/**
 * JWT（JSON Web Token）生成與驗證相關的組態屬性。
 * <p>
 * 這些屬性通常從 {@code application.properties} 或 {@code application.yml} 檔案中載入。
 * 使用 {@code @ConfigurationProperties(prefix = "jwt")} 將 {@code jwt.*}
 * 前綴的屬性綁定到此類別的欄位。
 * </p>
 */
@Component // 確保此類別被 Spring 視為一個 Bean
@ConfigurationProperties(prefix = "jwt") // 指定屬性前綴
@Data // Lombok: 自動生成 getters, setters, toString, equals, hashCode 方法
public class JwtConfigProperties {

    /**
     * 用於簽署和驗證 JWT 的密鑰。
     * <p>
     * 這應該是一個強固的、Base64 編碼的字串。
     * **重要提示：** 在生產環境中，此密鑰應外部化管理（例如，透過環境變數或密鑰管理服務），
     * 不應硬編碼或提交到版本控制系統中。
     * </p>
     * <p>
     * 範例 (application.yml):
     * {@code secretKey: "your-super-secret-base64-encoded-key"}
     * </p>
     */
    private String secretKey;

    /**
     * JWT 的發行者（iss）聲明。識別發行 JWT 的主體。
     * <p>
     * 範例 (application.yml): {@code issuer: "my-auth-service"}
     * </p>
     */
    private String issuer;

    /**
     * JWT 的受眾（aud）聲明。識別 JWT 的預期接收者。
     * <p>
     * 範例 (application.yml): {@code audience: "my-app-client"}
     * </p>
     */
    private String audience;

    /**
     * Access Token 的過期時間（毫秒）。
     * <p>
     * 預設值：3,600,000 毫秒（1 小時）。
     * </p>
     * <p>
     * 範例 (application.yml): {@code accessTokenExpirationMs: 3600000}
     * </p>
     */
    private long accessTokenExpirationMs = 3600000L; // 1 hour in milliseconds

    /**
     * Refresh Token 的過期時間（毫秒）。
     * <p>
     * 預設值：86,400,000 毫秒（24 小時）。
     * </p>
     * <p>
     * 範例 (application.yml): {@code refreshTokenExpirationMs: 86400000}
     * </p>
     */
    private long refreshTokenExpirationMs = 86400000L; // 24 hours in milliseconds

    private BlacklistProperties blacklist;

    @Data
    public static class BlacklistProperties {
        /**
         * JTI 黑名單清理任務的固定執行頻率（毫秒）。
         * <p>
         * 預設值：3,600,000 毫秒（1 小時）。
         * </p>
         * <p>
         * 用於 {@link com.jwt.auth.security.JwtTokenProvider#cleanupInvalidatedJtis()}
         * 方法的 {@code @Scheduled} 註解。
         * </p>
         */
        private long cleanupFixedRateMs = 3600000L; // 1 hour
        /**
         * JTI 在其對應的 Token 過期後，在黑名單中額外保留的緩衝時間（毫秒）。
         * <p>
         * 預設值：86,400,000 毫秒（24 小時）。
         * </p>
         * <p>
         * 用於 {@link com.jwt.auth.security.JwtTokenProvider#cleanupInvalidatedJtis()}
         * 方法，以確保已過期的 JTI 不會立即被清除。
         * </p>
         */
        private long cleanupBufferMs = 86400000L; // 24 hours
    }
}
