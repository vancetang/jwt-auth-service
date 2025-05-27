# 協調者模式 - 任務執行報告 (Coordinator Mode - Task Execution Report)

本報告總結了在 JWT 認證微服務開發過程中，透過協調者模式執行的所有主要子任務及其成果。

## 子任務 #1: 初始化 Spring Boot 專案 (PowerShell)

*   **任務描述:**
    *   提供一個 PowerShell 指令稿，用於初始化 Spring Boot 專案，包含指定的依賴和設定，並執行建置。
*   **Worker 執行結果:**
    *   成功產生 `init_spring_boot.ps1` 指令稿。
    *   該指令稿能從 `start.spring.io` 下載專案原始碼 (使用 `com.example.jwt-auth-service` 作為 ArtifactId，Java 21，Spring Boot 3.3.0)。
    *   依賴項包括：Spring Web, Lombok, Spring Security。
    *   指令稿會自動解壓縮專案並使用 `mvnw.cmd package` 進行建置。

## 子任務 #2: 產生 `spec.md` 和 `todolist.md`

*   **任務描述:**
    *   建立 `spec.md` 檔案，包含專案的技術規格、UML 圖、API 規劃等。
    *   建立 `todolist.md` 檔案，列出初步的開發任務。
*   **Worker 執行結果:**
    *   成功產生 `spec.md`，內容包含：技術選型、API 規劃 (含 Mermaid 流程圖、端點定義、JWT Claims 表)、主要流程圖 (循序圖)、物件關聯圖 (預留位置) 及安全性設計。
    *   成功產生 `todolist.md`，包含詳細的 Markdown 格式任務清單。

## 子任務 #3: 實作 JWT Token 核心功能

*   **任務描述:**
    *   實現 JWT 的生成與驗證核心機制。包括修改 `pom.xml` 以引入 JWT 相關依賴，創建 `JwtConfigProperties.java` 用於管理 JWT 設定，更新 `application.yml` 以配置相關屬性，以及創建 `JwtTokenProvider.java` 作為 JWT 操作的主要服務類。
*   **Worker 執行結果:**
    *   `pom.xml`: 成功加入 `io.jsonwebtoken:jjwt-api`, `jjwt-impl`, `jjwt-jackson` (版本 0.12.5) 依賴。
    *   `JwtConfigProperties.java` (`src/main/java/com/jwt/auth/config/`): 成功創建，用於定義 JWT 相關組態（如密鑰、發行者、過期時間）。(註：Worker 根據專案 `pom.xml` 的 `groupId` 將基礎 package 設為 `com.jwt.auth`)
    *   `application.yml` (`src/main/resources/`): 成功更新，加入 `jwt.secretKey`, `jwt.issuer`, `jwt.audience`, `jwt.accessTokenExpirationMs`, `jwt.refreshTokenExpirationMs` 等屬性。
    *   `JwtTokenProvider.java` (`src/main/java/com/jwt/auth/security/`): 成功創建，包含以下功能：
        *   `@PostConstruct init()`: 用於從配置初始化 `SecretKey`。
        *   `generateAccessToken(String userId, List<String> roles)`: 生成 Access Token。
        *   `generateRefreshToken(String userId)`: 生成 Refresh Token。
        *   `validateToken(String token)`: 驗證 Token (簽名、過期)。
        *   `getClaims(String token)`: 從 Token 中提取聲明。
        *   `getUserIdFromToken(String token)`: 從 Token 中提取使用者 ID。
        *   `getJtiFromToken(String token)`: 從 Token 中提取 JTI。
        *   `isTokenExpired(String token)`: 檢查 Token 是否過期。

## 子任務 #4: 實作 `/auth/login` API Endpoint 與初步的 Token 失效管理

*   **任務描述:**
    *   創建 `/auth/login` API 端點，相關的 DTOs (`LoginRequest`, `JwtAuthenticationResponse`)，以及 `AuthService` 進行登入邏輯處理。
    *   更新 `JwtTokenProvider` 以支援初步的 JTI 黑名單機制（基於記憶體）。
    *   建立初步的 Spring Security 配置 (`SecurityConfig.java`)。
*   **Worker 執行結果:**
    *   DTOs 創建成功：
        *   `LoginRequest.java` (`com.jwt.auth.payload.request`)
        *   `JwtAuthenticationResponse.java` (`com.jwt.auth.payload.response`)
    *   `JwtTokenProvider.java` 更新：
        *   新增 `private final Set<String> invalidatedJtis = ConcurrentHashMap.newKeySet();` 用於存儲失效的 JTI。
        *   新增 `invalidateToken(String token)` 方法，將 JTI 加入上述集合。
        *   修改 `validateToken(String token)` 方法，增加對 `invalidatedJtis` 集合的檢查。
    *   `AuthService.java` (`com.jwt.auth.service`) 創建成功：
        *   包含 `loginUser(LoginRequest loginRequest)` 方法，實現了基於硬編碼用戶的認證邏輯。
        *   包含 `logoutUser(String token)` 方法，調用 `jwtTokenProvider.invalidateToken()`。
    *   `AuthController.java` (`com.jwt.auth.controller`) 創建成功：
        *   包含 `POST /api/auth/login` 端點處理。
    *   `SecurityConfig.java` (`com.jwt.auth.config`) 初版創建成功：
        *   配置允許對 `/api/auth/**` 路徑的公開訪問。

## 子任務 #5: 實作 `/auth/logout`, `/auth/refresh` API 及 JWT 認證過濾器

*   **任務描述:**
    *   新增 `/auth/logout` 和 `/auth/refresh` API 端點。
    *   實現 `JwtAuthenticationFilter` 以處理請求中的 JWT 認證。
    *   創建 `CustomUserDetailsService`。
    *   創建 `UserInfoResponse` DTO 並實現 `/user/info` 端點。
    *   更新 `SecurityConfig` 以整合 JWT 過濾器。
*   **Worker 執行結果:**
    *   `RefreshTokenRequest.java` (`com.jwt.auth.payload.request`) DTO 創建成功。
    *   `AuthController.java` 更新：
        *   新增 `POST /api/auth/logout` 端點。
        *   新增 `POST /api/auth/refresh` 端點。
        *   新增 `GET /api/auth/user/info` 端點 (受 `@PreAuthorize("isAuthenticated()")` 保護)。
    *   `AuthService.java` 更新：
        *   新增 `refreshAccessToken(String requestRefreshToken)` 方法 (此階段未實現 Refresh Token 輪換)。
    *   `JwtAuthenticationFilter.java` (`com.jwt.auth.security`) 創建成功：
        *   繼承 `OncePerRequestFilter`，從 `Authorization` 標頭提取 JWT，驗證並設定 Spring Security 上下文。
    *   `CustomUserDetailsService.java` (`com.jwt.auth.service`) 創建成功：
        *   提供 `UserDetailsService` 的基本實現。
    *   `SecurityConfig.java` 更新：
        *   將 `JwtAuthenticationFilter` 加入到 Spring Security 過濾鏈中。
        *   啟用 `@EnableMethodSecurity` 以支援方法級別的權限控制。
        *   允許 Swagger UI 路徑 (`/swagger-ui/**`, `/v3/api-docs/**`) 的公開訪問。
    *   `UserInfoResponse.java` (`com.jwt.auth.payload.response`) DTO 創建成功。

## 子任務 #6: 全面檢視並補全函式級註解

*   **任務描述:**
    *   為專案中主要的 Java 類及其公開方法、建構函數、重要欄位等添加或更新符合標準的 Javadoc 註解，並使用繁體中文。
*   **Worker 執行結果:**
    *   成功為以下所有指定的 Java 檔案及其組件更新了 Javadoc 註解 (使用繁體中文)：
        *   `com.jwt.auth.config.JwtConfigProperties.java`
        *   `com.jwt.auth.config.SecurityConfig.java`
        *   `com.jwt.auth.controller.AuthController.java`
        *   `com.jwt.auth.payload.request.LoginRequest.java`
        *   `com.jwt.auth.payload.request.RefreshTokenRequest.java`
        *   `com.jwt.auth.payload.response.JwtAuthenticationResponse.java`
        *   `com.jwt.auth.payload.response.UserInfoResponse.java`
        *   `com.jwt.auth.security.JwtAuthenticationFilter.java`
        *   `com.jwt.auth.security.JwtTokenProvider.java`
        *   `com.jwt.auth.service.AuthService.java`
        *   `com.jwt.auth.service.CustomUserDetailsService.java`

## 子任務 #7: 分析現有 Token 失效機制並提出改進建議

*   **任務描述:**
    *   提供一份詳細的分析報告，評估當前基於 JTI 的記憶體黑名單機制，並針對多服務實例部署的擴展性、記憶體管理以及 Refresh Token 連帶失效等問題提出改進建議。
*   **Worker 執行結果:**
    *   成功提交了一份 Markdown 格式的分析報告，包含以下關鍵點：
        *   **目前機制評估**：肯定了 `ConcurrentHashMap.newKeySet()` 在單實例下的線程安全性和低碰撞率，但指出了其非持久化、記憶體增長和不適用於多實例的問題。
        *   **多實例擴展方案**：探討了使用集中式快取 (如 Redis，推薦) 和資料庫存儲 JTI 黑名單的方案，比較了其優缺點。
        *   **記憶體管理**：建議為記憶體黑名單實現基於 Token 原始過期時間的清理策略，並提供了具體思路。
        *   **Refresh Token 連帶失效**：分析了其必要性，並提出了在 Access Token 中包含 Refresh Token JTI (`rt_jti`) 的實現思路。
        *   **總結與建議**：建議短期內優化記憶體清理，長期遷移到 Redis 並實現 Refresh Token 輪換與連帶失效。

## 子任務 #8: 實作記憶體中失效 JTI 黑名單的自動清理機制

*   **任務描述:**
    *   根據先前分析報告中的建議，為記憶體中的 JTI 黑名單實現自動清理機制，以防止記憶體無限增長。
*   **Worker 執行結果:**
    *   `JwtConfigProperties.java`: 新增 `blacklistCleanupFixedRateMs` 和 `blacklistCleanupBufferMs` 組態屬性，用於控制清理任務的執行頻率和 JTI 在過期後的緩衝保留時間。
    *   `application.yml`: 加入了對應上述屬性的組態 `jwt.blacklist.cleanupFixedRateMs` 和 `jwt.blacklist.cleanupBufferMs`。
    *   `JwtTokenProvider.java`:
        *   將 JTI 黑名單的數據結構從 `Set<String>` 修改為 `Map<String, Long> invalidatedJtisWithTimestamp`，用於存儲 JTI 及其對應 Token 的原始過期時間戳。
        *   更新 `invalidateToken(String token)` 方法，使其在記錄 JTI 時同時記錄其原始過期時間戳 (若無法從 Token 解析出過期時間，則使用備援策略)。
        *   更新 `validateToken(String token)` 方法，以適應新的黑名單數據結構。
        *   新增 `@Scheduled cleanupInvalidatedJtis()` 方法，該方法根據配置的頻率和緩衝時間，定期從 `invalidatedJtisWithTimestamp` 中移除已確實過期的 JTI。
    *   提供了關於如何在 Spring Boot 主應用程式類上添加 `@EnableScheduling` 以啟用排程任務的說明。

## 子任務 #9: 實作 Refresh Token 的連帶失效機制

*   **任務描述:**
    *   實現 Refresh Token 的連帶失效機制，確保在 Access Token 因登出而失效時，其關聯的 Refresh Token 也一同失效。同時實現 Refresh Token 輪換 (Rotation) 機制。
*   **Worker 執行結果:**
    *   `JwtTokenProvider.java` 更新：
        *   `generateAccessToken()` 方法更新，在其產生的 Access Token 中新增 `rt_jti` (Refresh Token JTI) Claim，用以關聯對應的 Refresh Token。
        *   `invalidateToken()` 方法更新，在使 Access Token 失效時，會嘗試從 Access Token 中提取 `rt_jti`，並將此關聯的 Refresh Token JTI 也加入黑名單。
        *   新增 `invalidateJti(String jti, Long originalExpiryTimestamp)` 方法，用於更精確地使特定 JTI 失效（主要用於 Refresh Token 輪換時使舊 Refresh Token 失效）。
        *   新增 `getRefreshTokenJtiFromAccessTokenUnsafe()` 輔助方法，用於從 Access Token 中安全地提取 `rt_jti`。
    *   `AuthService.java` 更新：
        *   `loginUser()` 方法更新，在生成 Access Token 時，會將對應 Refresh Token 的 JTI 傳遞給 `generateAccessToken()` 方法，以便嵌入到 Access Token 中。
        *   `refreshAccessToken()` 方法更新，實現了 Refresh Token 輪換：
            1.  驗證傳入的舊 Refresh Token。
            2.  產生一個全新的 Refresh Token 和一個新的 Access Token。
            3.  新的 Access Token 會關聯到新的 Refresh Token 的 JTI。
            4.  舊的 Refresh Token 的 JTI 會被明確地加入到黑名單中。
            5.  回應中返回新的 Access Token 和新的 Refresh Token。

## 子任務 #10 & #11: 更新 `todolist.md` 和 `README.md`

*   **任務描述:**
    *   根據專案的最新進展更新 `todolist.md` 文件，標記已完成的任務。
    *   創建 `README.md` 文件，包含專案描述、檔案結構、使用技術、安裝執行方式等。
*   **Worker 執行結果:**
    *   `todolist.md`: 成功使用提供的最新內容覆蓋了原文件，準確反映了所有已完成的開發任務。
    *   `README.md`: 成功創建，內容完整，包括專案概述、詳細的檔案結構說明、使用的主要技術棧、各核心檔案的功能解釋，以及詳細的環境需求、配置步驟（特別強調了 `jwt.secretKey` 的重要性）和執行指令。API 測試端點和預設帳號資訊也已包含。
    *   Worker 指出其中一個更新任務（`todolist.md` 或 `README.md`）在其執行時被視為冗餘，因為內容與前一任務產出相同，但最終結果符合要求。

---
報告完畢。
