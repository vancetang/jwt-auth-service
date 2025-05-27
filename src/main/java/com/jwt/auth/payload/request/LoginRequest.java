package com.jwt.auth.payload.request;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

/**
 * 用於使用者登入請求的資料傳輸物件 (DTO)。
 * <p>
 * 此類別封裝了使用者在登入過程中提供的使用者名稱和密碼。
 * 主要用於接收來自客戶端的登入憑證。
 * </p>
 */
@Data // Lombok: 自動生成 getters, setters, toString, equals, hashCode 方法
// 備註：如果不需要 equals/hashCode/toString 等方法，可以考慮使用 @Getter @Setter 組合
public class LoginRequest {

    /**
     * 嘗試登入的使用者名稱。
     * <p>
     * 此欄位為必填項。
     * </p>
     */
    private String username;

    /**
     * 嘗試登入的使用者密碼。
     * <p>
     * 此欄位為必填項。
     * </p>
     */
    private String password;
}
