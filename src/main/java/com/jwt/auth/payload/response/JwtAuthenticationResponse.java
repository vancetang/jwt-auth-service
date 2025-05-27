package com.jwt.auth.payload.response;

import lombok.Data;

/**
 * 用於 JWT 身份驗證回應的資料傳輸物件 (DTO)。
 * <p>
 * 此類別封裝了在成功驗證後提供給客戶端的存取權杖 (Access Token)、
 * 刷新權杖 (Refresh Token) 以及權杖類型。
 * </p>
 */
@Data // Lombok: 自動生成 getters, setters, toString, equals, hashCode 方法
// 備註：如果不需要所有 @Data 的功能，可以考慮使用 @Getter @Setter
public class JwtAuthenticationResponse {

    /**
     * JWT 存取權杖 (Access Token)。
     * <p>
     * 用於授權客戶端存取受保護的資源。
     * </p>
     */
    private String accessToken;

    /**
     * JWT 刷新權杖 (Refresh Token)。
     * <p>
     * 用於在存取權杖過期後，獲取新的存取權杖，而無需使用者重新登入。
     * </p>
     */
    private String refreshToken;

    /**
     * 權杖類型，通常為 "Bearer"。
     * <p>
     * 這是 JWT 在 HTTP {@code Authorization} 標頭中使用的標準前綴。
     * 預設值為 "Bearer"。
     * </p>
     */
    private String tokenType = "Bearer";

    /**
     * 建構一個新的 {@code JwtAuthenticationResponse} 物件。
     *
     * @param accessToken  存取權杖。
     * @param refreshToken 刷新權杖。
     */
    public JwtAuthenticationResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    // Lombok 的 @Data 註解會自動生成 getters 和 setters。
    // 如果需要特定的建構函數或其他方法，可以在此處添加。
}
