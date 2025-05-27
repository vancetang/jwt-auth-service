package com.jwt.auth.payload.response;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 用於返回使用者資訊的資料傳輸物件 (DTO)。
 * <p>
 * 此類別封裝了使用者的唯一識別碼 (ID)、角色列表以及一條自訂訊息。
 * 通常在使用者請求其個人資料時作為回應返回。
 * </p>
 */
@Data // Lombok: 自動生成 getters, setters, toString, equals, hashCode 方法
@NoArgsConstructor // Lombok: 自動生成無參數建構函數
@AllArgsConstructor // Lombok: 自動生成包含所有參數的建構函數
public class UserInfoResponse {

    /**
     * 使用者的唯一識別碼。
     * <p>
     * 通常對應於 JWT 中的 subject ({@code sub}) 聲明。
     * </p>
     */
    private String userId;

    /**
     * 分配給使用者的角色列表。
     * <p>
     * 範例：{@code ["ROLE_USER", "ROLE_ADMIN"]}
     * </p>
     */
    private List<String> roles;

    /**
     * 提供額外資訊或狀態的訊息。
     * <p>
     * 範例："使用者資訊檢索成功。"
     * </p>
     */
    private String message;

    // 可選：如果需要，可以在此處添加其他使用者特定的詳細資訊
    // private String email; // 例如：使用者的電子郵件地址
    // private String displayName; // 例如：使用者的顯示名稱
}
