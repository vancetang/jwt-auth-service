# JWT 認證微服務 (JWT Authentication Microservice)

## 專案描述

*   簡述：這是一個使用 Spring Boot 實現的 JWT (JSON Web Token) 認證微服務。
*   主要功能：提供安全的用戶登入、登出、Token 刷新及使用者資訊獲取 API。
*   實現了基於 JTI 的 Token 黑名單機制、Refresh Token 輪換、以及相關安全性措施。

## 檔案結構

```
jwt-auth-service/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/jwt/auth/  # 實際 package name
│   │   │       ├── config/         # Spring Security 及 JWT 設定類
│   │   │       ├── controller/     # API 端點控制器
│   │   │       ├── model/          # (目前未使用，保留給可能的實體模型)
│   │   │       ├── payload/        # API 請求與回應的 DTOs
│   │   │       ├── security/       # JWT 核心邏輯 (Provider, Filter)
│   │   │       └── service/        # 業務邏輯服務 (AuthService, CustomUserDetailsService)
│   │   └── resources/
│   │       ├── application.yml     # Spring Boot 應用程式配置
│   │       └── static/           # 靜態資源 (目前未使用)
│   │       └── templates/        # 模板引擎 (目前未使用)
│   └── test/                   # 單元測試與整合測試 (目前尚未實現)
├── pom.xml                     # Maven 專案設定檔
├── README.md                   # 本文件
├── spec.md                     # 服務規格文件
└── todolist.md                 # 任務清單
```
*(註：`com/jwt/auth/` 是根據專案實際情況確定的 package name)*

## 使用技術

*   **後端框架**: Spring Boot 3.5.0
*   **語言**: Java 21
*   **建置工具**: Apache Maven
*   **核心依賴**:
    *   Spring Web (RESTful API)
    *   Spring Security (安全框架)
    *   Lombok (簡化樣板程式碼)
    *   `io.jsonwebtoken:jjwt` (JWT 函式庫, 版本 0.12.5)
*   **認證機制**: JSON Web Tokens (JWT)
    *   Access Token + Refresh Token (具備輪換機制)
    *   HMAC-SHA512 簽章演算法
    *   JTI 黑名單 (記憶體實現，具備基於 Token 過期時間的自動清理機制)

## 主要檔案說明

*   `com.jwt.auth.config.JwtConfigProperties.java`: JWT 相關配置屬性類，從 `application.yml` 載入設定。
*   `com.jwt.auth.config.SecurityConfig.java`: Spring Security 的主要配置，定義安全過濾器鏈、HTTP 安全規則及 JWT 過濾器的整合。
*   `com.jwt.auth.controller.AuthController.java`: 處理所有認證相關 API 端點，包括 `/api/auth/login`, `/api/auth/logout`, `/api/auth/refresh`, 以及受保護的 `/api/auth/user/info`。
*   `com.jwt.auth.payload.request.*`: API 請求的資料傳輸物件 (DTOs)，如 `LoginRequest.java` 和 `RefreshTokenRequest.java`。
*   `com.jwt.auth.payload.response.*`: API 回應的資料傳輸物件 (DTOs)，如 `JwtAuthenticationResponse.java` 和 `UserInfoResponse.java`。
*   `com.jwt.auth.security.JwtTokenProvider.java`: 核心服務，負責 JWT 的產生、驗證、解析聲明、以及 JTI 黑名單管理（包括儲存 JTI 及其原始過期時間和定期清理任務）。
*   `com.jwt.auth.security.JwtAuthenticationFilter.java`: Spring Security 過濾器，攔截 HTTP 請求，從 `Authorization` 標頭提取 JWT，驗證 Token，並在 Spring Security 上下文中設定用戶認證資訊。
*   `com.jwt.auth.service.AuthService.java`: 處理用戶認證 (目前為硬編碼)、Token 管理 (登入、登出、刷新 Access Token 並實現 Refresh Token 輪換) 等核心業務邏輯。
*   `com.jwt.auth.service.CustomUserDetailsService.java`: Spring Security 的 `UserDetailsService` 接口的簡單實現，主要用於滿足 Spring Security 架構需求，實際的角色和權限由 `JwtAuthenticationFilter` 從 Token 中提取。
*   `application.yml`: 應用程式的主要配置文件，包含 JWT 密鑰、發行者、受眾、Token 過期時間、JTI 黑名單清理排程的頻率和緩衝時間等。
*   `spec.md`: 包含服務的技術選型、API 設計、流程圖（循序圖、流程圖）等詳細規格。
*   `todolist.md`: 專案開發的任務清單與進度追蹤。

## 安裝及執行方式

### 環境需求
*   Java JDK 21 或更高版本
*   Apache Maven 3.6+ (如果需要手動建置或不使用 Maven Wrapper)

### 取得專案
*   `git clone <repository-url>` (如果已推送到 Git 倉庫)
*   或者，將專案檔案解壓縮到本地目錄。

### 配置
1.  開啟 `src/main/resources/application.yml`。
2.  **重要**: 修改 `jwt.secretKey` 的值。
    *   這必須是一個強固的、Base64 編碼的字串。
    *   對於 HS512 演算法，建議密鑰長度至少為 64 字節 (512 位元)。
    *   可以使用以下命令產生一個範例 (Linux/macOS): `openssl rand -base64 64`
    *   **請勿在生產環境中使用範例中或預設的密鑰！**
3.  其他 JWT 相關配置如 `issuer`, `audience`, `accessTokenExpirationMs`, `refreshTokenExpirationMs`, 以及 `blacklist` 下的清理設定，均可依需求調整。

### 執行專案 (於專案根目錄下使用 PowerShell 或其他終端)

```powershell
# 清理並建置專案 (使用 Maven Wrapper)
./mvnw.cmd clean package

# 如果沒有 mvnw.cmd 或遇到權限問題，且已安裝全域 Maven:
# mvn clean package

# 執行應用程式
java -jar target/jwt-auth-service-0.0.1-SNAPSHOT.jar
# 注意：.jar 檔案的實際名稱可能因 pom.xml 中的 <artifactId> 和 <version> 而異。
# 目前 pom.xml 中的 artifactId 為 'jwt-auth-service'，version 為 '0.0.1-SNAPSHOT'。
```

### API 測試
*   應用程式啟動後，預設運行在 `http://localhost:8080` (除非在 `application.yml` 中修改了 `server.port`)。
*   可使用 Postman、curl 或其他 API 測試工具與以下端點互動：
    *   **使用者登入**: `POST /api/auth/login`
        *   請求 Body (JSON): `{ "username": "user", "password": "password" }`
        *   成功回應會包含 `accessToken` 和 `refreshToken`。
    *   **刷新 Access Token**: `POST /api/auth/refresh`
        *   請求 Body (JSON): `{ "refreshToken": "your_refresh_token_here" }`
        *   成功回應會包含新的 `accessToken` 和新的 `refreshToken` (Refresh Token 輪換)。
    *   **使用者登出**: `POST /api/auth/logout`
        *   請求 Header: `Authorization: Bearer your_access_token_here`
        *   成功回應為 HTTP 200 OK 及訊息。
    *   **獲取使用者資訊**: `GET /api/auth/user/info`
        *   請求 Header: `Authorization: Bearer your_access_token_here`
        *   成功回應會包含使用者 ID 和角色。
*   **預設硬編碼的使用者帳號**:
    *   使用者: `user` / 密碼: `password` (角色: `ROLE_USER`)
    *   管理員: `admin` / 密碼: `adminpass` (角色: `ROLE_ADMIN`, `ROLE_USER`)

*(請將 `<repository-url>` 替換為實際的 Git 倉庫 URL)*
