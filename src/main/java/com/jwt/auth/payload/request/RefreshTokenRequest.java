package com.jwt.auth.payload.request;

import lombok.Data;

/**
 * 用於刷新權杖請求的資料傳輸物件 (DTO)。
 * <p>
 * 此類別封裝了客戶端提供的刷新權杖 (Refresh Token)，
 * 用於請求一個新的存取權杖 (Access Token)。
 * </p>
 */
@Data // Lombok: 自動生成 getters, setters, toString, equals, hashCode 方法
public class RefreshTokenRequest {

    /**
     * 刷新權杖字串。
     * <p>
     * 此欄位為必填項，用於向認證伺服器請求新的存取權杖。
     * </p>
     */
    private String refreshToken;
}
