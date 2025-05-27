package com.jwt.auth.security;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.jwt.auth.config.JwtConfigProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT 權杖服務類別，負責 JWT 的生成、驗證、聲明提取以及基於 JTI 的權杖失效管理與清理。
 * <p>
 * 此服務依賴於 {@link JwtConfigProperties} 中定義的組態屬性來進行操作。
 * 主要功能包括：
 * <ul>
 * <li>初始化用於簽章的密鑰 ({@link #init()})。</li>
 * <li>生成存取權杖 ({@link #generateAccessToken(String, List)}) 和刷新權杖
 * ({@link #generateRefreshToken(String)})。</li>
 * <li>驗證權杖的有效性 ({@link #validateToken(String)})，包括簽名、過期時間和 JTI 是否已失效。</li>
 * <li>使權杖失效 ({@link #invalidateToken(String)})，通常用於登出操作。</li>
 * <li>從權杖中提取聲明 ({@link #getClaims(String)})、使用者 ID
 * ({@link #getUserIdFromToken(String)})
 * 和 JWT ID ({@link #getJtiFromToken(String)})。</li>
 * <li>檢查權杖是否過期 ({@link #isTokenExpired(String)})。</li>
 * </ul>
 * </p>
 */
@Component
@Slf4j // Lombok: 自動生成日誌記錄器
public class JwtTokenProvider {

    @Autowired
    private JwtConfigProperties jwtConfigProperties; // JWT 組態屬性
    private SecretKey secretKey; // 用於 JWT 簽章的密鑰
    // 將 invalidatedJtis 修改為 Map，用於儲存 JTI 及其對應 Token 的原始過期時間戳
    private final Map<String, Long> invalidatedJtisWithTimestamp = new ConcurrentHashMap<>();

    /**
     * 初始化 {@link SecretKey} 物件。
     * <p>
     * 此方法在 Bean 建構完成後 ({@code @PostConstruct}) 自動呼叫。
     * 它從 {@link JwtConfigProperties#getSecretKey()} 獲取 Base64 編碼的密鑰字串，
     * 將其解碼並轉換為 {@link SecretKey} 物件，以供後續的權杖簽署與驗證操作使用。
     * 確保在執行任何權杖操作之前，密鑰已準備就緒。
     * </p>
     * 
     * @throws RuntimeException 如果 Base64 密鑰解碼失敗或密鑰長度不足以適用於所選算法。
     */
    @PostConstruct
    public void init() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(jwtConfigProperties.getSecretKey());
            this.secretKey = Keys.hmacShaKeyFor(keyBytes);
            log.info("JWT SecretKey 初始化成功。演算法：{}", this.secretKey.getAlgorithm());
        } catch (IllegalArgumentException e) {
            log.error(
                    "解碼 Base64 密鑰時發生錯誤：{}。請確認密鑰已正確 Base64 編碼且長度符合演算法需求。",
                    e.getMessage());
            // Potentially rethrow or handle as a critical startup failure
            throw new RuntimeException(
                    "因 Base64 編碼錯誤或密鑰長度不足，無法初始化 JWT SecretKey。", e);
        }
    }

    /**
     * 為指定的使用者 ID 和角色列表生成一個存取權杖 (Access Token)。
     * <p>
     * 存取權杖包含以下標準聲明和自訂聲明：
     * <ul>
     * <li>{@code sub} (Subject): 使用者 ID。</li>
     * <li>{@code roles}: 使用者角色列表。</li>
     * <li>{@code typ} (Type): 設定為 "Bearer"。</li>
     * <li>{@code jti} (JWT ID): 唯一的權杖識別碼。</li>
     * <li>{@code iss} (Issuer): 從 {@link JwtConfigProperties} 獲取。</li>
     * <li>{@code aud} (Audience): 從 {@link JwtConfigProperties} 獲取。</li>
     * <li>{@code iat} (Issued At): 權杖發行時間。</li>
     * <li>{@code exp} (Expiration Time): 權杖過期時間，根據
     * {@link JwtConfigProperties#getAccessTokenExpirationMs()} 計算。</li>
     * </ul>
     * 權杖使用 HS512 算法和初始化的密鑰進行簽署。
     * </p>
     *
     * @param userId          使用者的唯一識別碼。
     * @param roles           與使用者關聯的角色列表。
     * @param refreshTokenJti 對應的 Refresh Token 的 JTI，用於實現連帶失效。
     * @return 已簽署的 JWT 存取權杖字串。
     */
    public String generateAccessToken(String userId, List<String> roles, String refreshTokenJti) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtConfigProperties.getAccessTokenExpirationMs());
        String accessTokenJti = UUID.randomUUID().toString(); // Access Token 自身的 JTI

        // 產生 Access Token，audience 改用 claim("aud", ...)
        return Jwts.builder()
                .subject(userId)
                .claim("roles", roles)
                .claim("typ", "Bearer") // Token Type
                .claim("rt_jti", refreshTokenJti) // 新增：關聯的 Refresh Token JTI
                .id(accessTokenJti) // Access Token 自身的 JTI
                .issuer(jwtConfigProperties.getIssuer())
                .claim("aud", jwtConfigProperties.getAudience())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey, Jwts.SIG.HS512) // Ensure algorithm matches key strength
                .compact();
    }

    /**
     * 為指定的使用者 ID 生成一個刷新權杖 (Refresh Token)。
     * <p>
     * 刷新權杖包含以下標準聲明和自訂聲明：
     * <ul>
     * <li>{@code sub} (Subject): 使用者 ID。</li>
     * <li>{@code typ} (Type): 設定為 "Refresh"。</li>
     * <li>{@code jti} (JWT ID): 唯一的權杖識別碼。</li>
     * <li>{@code iss} (Issuer): 從 {@link JwtConfigProperties} 獲取。</li>
     * <li>{@code aud} (Audience): 從 {@link JwtConfigProperties} 獲取。</li>
     * <li>{@code iat} (Issued At): 權杖發行時間。</li>
     * <li>{@code exp} (Expiration Time): 權杖過期時間，根據
     * {@link JwtConfigProperties#getRefreshTokenExpirationMs()} 計算。</li>
     * </ul>
     * 權杖使用 HS512 算法和初始化的密鑰進行簽署。
     * </p>
     *
     * @param userId 使用者的唯一識別碼。
     * @return 已簽署的 JWT 刷新權杖字串。
     */
    public String generateRefreshToken(String userId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtConfigProperties.getRefreshTokenExpirationMs());
        String jti = UUID.randomUUID().toString();

        // 產生 Refresh Token，audience 改用 claim("aud", ...)
        return Jwts.builder()
                .subject(userId)
                .claim("typ", "Refresh") // Token Type
                .id(jti) // JWT ID
                .issuer(jwtConfigProperties.getIssuer())
                .claim("aud", jwtConfigProperties.getAudience())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey, Jwts.SIG.HS512) // Ensure algorithm matches key strength
                .compact();
    }

    /**
     * 驗證給定的 JWT 權杖。
     * <p>
     * 此方法檢查權杖的簽名有效性、是否過期、格式是否正確，以及其 JTI 是否已被標記為失效 (登出)。
     * </p>
     *
     * @param token 要驗證的 JWT 權杖字串。
     * @return 如果權杖有效且未失效，則返回 {@code true}；否則返回 {@code false}。
     */
    public boolean validateToken(String token) {
        if (token == null || token.isBlank()) {
            log.warn("驗證時發現權杖為空或為空白字串。");
            return false;
        }
        try {
            // Check if JTI is invalidated (logged out)
            String jti = getJtiFromTokenUnsafe(token); // Use unsafe method for JTI extraction before full validation
            if (jti != null && invalidatedJtisWithTimestamp.containsKey(jti)) {
                // 可選增強：檢查儲存的 expirationTime 是否已過期。
                // 但為了明確的登出語義，只要在黑名單中就視為失效。清理任務會負責移除。
                log.warn("驗證失敗：Token JTI ({}) 已失效（已登出）。", jti);
                return false;
            }

            Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException ex) { // Order matters: check expiration and invalidation before other structural
                                           // issues
            log.warn("JWT 權杖已過期：{}", ex.getMessage());
        } catch (SignatureException ex) {
            log.error("JWT 簽章無效：{}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.error("JWT 權杖無效：{}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("不支援的 JWT 權杖：{}", ex.getMessage());
        } catch (IllegalArgumentException ex) { // This can be thrown by getJtiFromTokenUnsafe or parser
            log.error("JWT claims 字串為空、null 或權杖結構無效：{}", ex.getMessage());
        }
        return false;
    }

    /**
     * 使給定的 JWT 權杖失效。
     * <p>
     * 此方法透過將權杖的 JTI (JWT ID) 添加到已失效 JTI 集合 ({@code invalidatedJtis}) 中來實現。
     * 主要用於實現登出功能。如果權杖無法解析或提取 JTI 失敗，則會記錄警告。
     * </p>
     *
     * @param token 要使其失效的 JWT 權杖字串。
     */
    public void invalidateToken(String token) {
        if (token == null || token.isBlank()) {
            log.warn("嘗試使權杖失效時發現權杖為空或為空白字串。");
            return;
        }
        try {
            String accessTokenJti = getJtiFromTokenUnsafe(token); // 獲取 Access Token 的 JTI
            Date accessTokenExpiry = getExpirationFromTokenUnsafe(token); // 獲取 Access Token 的原始過期時間

            if (accessTokenJti != null && accessTokenExpiry != null) {
                invalidatedJtisWithTimestamp.put(accessTokenJti, accessTokenExpiry.getTime());
                log.info("Access Token JTI {} 及原始過期時間 {} 已成功失效。", accessTokenJti,
                        accessTokenExpiry);

                // 嘗試提取並失效關聯的 Refresh Token JTI
                String refreshTokenJti = getRefreshTokenJtiFromAccessTokenUnsafe(token);
                if (refreshTokenJti != null) {
                    // 對於 rt_jti，我們使用 Access Token 的過期時間戳作為其在黑名單中的清理依據。
                    // 雖然 Refresh Token 的實際有效期可能更長，但這樣可以確保它至少和 Access Token 一起被考慮清理。
                    // 一個更精確的做法是，如果可能，獲取 Refresh Token 的實際過期時間。
                    // 但在僅有 Access Token 的情況下，這是一個合理的簡化。
                    invalidatedJtisWithTimestamp.put(refreshTokenJti, accessTokenExpiry.getTime());
                    log.info(
                            "關聯的 Refresh Token JTI {} 也已加入黑名單，並與 Access Token 的過期時間連動清理。",
                            refreshTokenJti);
                } else {
                    log.warn("Access Token JTI {} 在失效處理時未找到 rt_jti。", accessTokenJti);
                }

            } else if (accessTokenJti != null) { // Access Token JTI 存在，但無法獲取其過期時間
                long fallbackExpiry = System.currentTimeMillis() + jwtConfigProperties.getAccessTokenExpirationMs();
                invalidatedJtisWithTimestamp.put(accessTokenJti, fallbackExpiry);
                log.warn("Access Token JTI {} 因缺少原始過期時間，已使用備援過期時間 {} 進行失效處理。", accessTokenJti,
                        new Date(fallbackExpiry));
                // 在這種情況下，我們仍然嘗試處理 rt_jti
                String refreshTokenJti = getRefreshTokenJtiFromAccessTokenUnsafe(token);
                if (refreshTokenJti != null) {
                    invalidatedJtisWithTimestamp.put(refreshTokenJti, fallbackExpiry); // 使用相同的 fallback expiry
                    log.info("關聯的 Refresh Token JTI {} 也已使用備援過期時間加入黑名單。", refreshTokenJti);
                }
            } else {
                log.warn("權杖失效失敗：無法從 Access Token 擷取 JTI。");
            }
        } catch (Exception e) { // 捕獲解析 JTI/EXP 或其他潛在異常
            log.warn("權杖失效失敗，擷取 JTI/EXP 或其他處理時發生錯誤：{}。Token: {}", e.getMessage(), token);
        }
    }

    /**
     * 直接使一個 JTI 失效，通常用於 Refresh Token 的精確失效控制。
     *
     * @param jti                     要失效的 JTI。
     * @param originalExpiryTimestamp JTI 對應權杖的原始過期時間戳 (毫秒)。如果為 null，將使用備援策略。
     */
    public void invalidateJti(String jti, Long originalExpiryTimestamp) {
        if (jti == null || jti.isBlank()) {
            log.warn("嘗試使 JTI 失效時發現 JTI 為空或為空白字串。");
            return;
        }
        if (originalExpiryTimestamp != null) {
            invalidatedJtisWithTimestamp.put(jti, originalExpiryTimestamp);
            log.info("JTI {} 已成功失效，原始過期時間 {}。", jti,
                    new Date(originalExpiryTimestamp));
        } else {
            // 如果無法獲取 exp，存入一個預設的較長的存活時間（例如 Refresh Token 的有效期）
            long fallbackExpiry = System.currentTimeMillis() + jwtConfigProperties.getRefreshTokenExpirationMs();
            invalidatedJtisWithTimestamp.put(jti, fallbackExpiry);
            log.warn("JTI {} 因缺少原始過期時間，已使用備援過期時間 {} 進行失效處理。", jti,
                    new Date(fallbackExpiry));
        }
    }

    /**
     * 解析給定的 JWT 權杖並返回其聲明 (Claims)。
     * <p>
     * 此方法會驗證權杖的簽名。如果權杖無效 (例如簽名錯誤、格式錯誤)，則會拋出 {@link JwtException}。
     * </p>
     *
     * @param token 要解析的 JWT 權杖字串。
     * @return 從權杖中提取的 {@link Claims} 物件。
     * @throws JwtException             如果權杖無法成功解析或驗證 (例如，簽名無效、格式錯誤)。
     * @throws IllegalArgumentException 如果權杖字串為 {@code null} 或空白。
     */
    public Claims getClaims(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Token string cannot be null or empty.");
        }
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * 從 JWT 權杖中提取使用者 ID (subject)。
     *
     * @param token JWT 權杖字串。
     * @return 使用者 ID (通常是 {@code sub} 聲明的值)。
     * @throws JwtException             如果權杖無法成功解析或驗證。
     * @throws IllegalArgumentException 如果權杖字串為 {@code null} 或空白。
     */
    public String getUserIdFromToken(String token) {
        return getClaims(token).getSubject();
    }

    /**
     * 從 JWT 權杖中提取 JWT ID (jti)。
     *
     * @param token JWT 權杖字串。
     * @return JWT ID ({@code jti} 聲明的值)。
     * @throws JwtException             如果權杖無法成功解析或驗證。
     * @throws IllegalArgumentException 如果權杖字串為 {@code null} 或空白。
     */
    public String getJtiFromToken(String token) {
        return getClaims(token).getId();
    }

    /**
     * 從 JWT 權杖中提取 JWT ID (jti)，且不執行完整的簽名驗證。
     * <p>
     * 此方法主要用於檢查已失效 JTI 列表等情境，在這些情境下，權杖可能已過期，但仍需要其 JTI。
     * **警告：** 此方法不驗證權杖的簽名或過期時間。僅在完全理解安全隱患的情況下使用。
     * 它僅對權杖結構進行基本檢查並嘗試解析 Payload 中的 JTI。
     * </p>
     *
     * @param token JWT 權杖字串。
     * @return 如果解析成功，則返回 JWT ID (jti)；否則返回 {@code null}。
     */
    private String getJtiFromTokenUnsafe(String token) {
        if (token == null || token.isBlank() || !token.contains(".")) {
            return null; // Basic check for token structure
        }
        try {
            String[] splitToken = token.split("\\.");
            if (splitToken.length < 3) { // A JWT must have 3 parts
                log.warn("不安全的 JTI 擷取：權杖結構不足 3 部分。");
                return null;
            }
            // Payload is the second part
            byte[] payloadBytes = Decoders.BASE64URL.decode(splitToken[1]);
            String payloadString = new String(payloadBytes, java.nio.charset.StandardCharsets.UTF_8);

            // Simple manual parsing for "jti" - less robust than using a full parser
            // but avoids signature/expiration checks. For a more robust way, use a parser
            // configured to skip signature validation, if the library supports it.
            // ObjectMapper could also be used here if Jackson is a dependency.
            // Example: com.fasterxml.jackson.databind.ObjectMapper mapper = new
            // com.fasterxml.jackson.databind.ObjectMapper();
            // com.fasterxml.jackson.databind.JsonNode jsonNode =
            // mapper.readTree(payloadString);
            // return jsonNode.has("jti") ? jsonNode.get("jti").asText() : null;

            // Basic string search for "jti"
            // This is a simplified approach and might not be robust for all JSON
            // structures.
            // Consider using a proper JSON parsing library for more complex scenarios.
            String jtiClaim = "\"jti\":\"";
            int startIndex = payloadString.indexOf(jtiClaim);
            if (startIndex == -1) {
                return null;
            }
            startIndex += jtiClaim.length();
            int endIndex = payloadString.indexOf("\"", startIndex);
            if (endIndex == -1) {
                return null;
            }
            return payloadString.substring(startIndex, endIndex);

        } catch (IllegalArgumentException e) { // Catch Base64 decoding errors
            log.warn("不安全的 JTI 擷取：解碼權杖 payload 時發生錯誤。{}", e.getMessage());
            return null;
        } catch (Exception e) { // Catch any other unexpected errors during unsafe parsing
            log.warn("不安全的 JTI 擷取：發生未預期錯誤。{}", e.getMessage());
            return null;
        }
    }

    /**
     * 從 Access Token 中安全地提取關聯的 Refresh Token JTI (`rt_jti`) Claim，不執行完整簽名驗證。
     * <p>
     * **警告：** 此方法不驗證權杖的簽名或過期時間。僅在完全理解安全隱患的情況下使用。
     * </p>
     * 
     * @param accessToken Access Token 字串。
     * @return 如果解析成功且 Claim 存在，則返回 Refresh Token JTI 字串；否則返回 {@code null}。
     */
    private String getRefreshTokenJtiFromAccessTokenUnsafe(String accessToken) {
        if (accessToken == null || accessToken.isBlank() || !accessToken.contains(".")) {
            return null;
        }
        try {
            String[] splitToken = accessToken.split("\\.");
            if (splitToken.length < 3) {
                log.warn("不安全的 RT_JTI 擷取：Access Token 結構不足 3 部分。");
                return null;
            }
            byte[] payloadBytes = Decoders.BASE64URL.decode(splitToken[1]);
            String payloadString = new String(payloadBytes, java.nio.charset.StandardCharsets.UTF_8);

            String rtJtiClaimKey = "\"rt_jti\":\"";
            int startIndex = payloadString.indexOf(rtJtiClaimKey);
            if (startIndex == -1) {
                return null; // Claim not found
            }
            startIndex += rtJtiClaimKey.length();
            int endIndex = payloadString.indexOf("\"", startIndex);
            if (endIndex == -1) {
                return null; // Malformed claim
            }
            return payloadString.substring(startIndex, endIndex);

        } catch (Exception e) {
            log.warn("不安全的 RT_JTI 擷取：解析 Access Token payload 取得 rt_jti 時發生錯誤。{}", e.getMessage());
            return null;
        }
    }

    /**
     * 從 JWT 權杖中提取過期時間 (exp)，不執行完整簽名驗證。
     * <p>
     * 類似於 {@link #getJtiFromTokenUnsafe(String)}，此方法用於從可能已過期或簽名無效的權杖中提取資訊。
     * **警告：** 此方法不驗證權杖的簽名。僅在完全理解安全隱患的情況下使用。
     * </p>
     * 
     * @param token JWT 權杖字串。
     * @return 如果解析成功，則返回 {@link Date} 形式的過期時間；否則返回 {@code null}。
     */
    private Date getExpirationFromTokenUnsafe(String token) {
        if (token == null || token.isBlank() || !token.contains(".")) {
            return null;
        }
        try {
            String[] splitToken = token.split("\\.");
            if (splitToken.length < 3) {
                log.warn("不安全的 EXP 擷取：權杖結構不足 3 部分。");
                return null;
            }
            byte[] payloadBytes = Decoders.BASE64URL.decode(splitToken[1]);
            String payloadString = new String(payloadBytes, java.nio.charset.StandardCharsets.UTF_8);

            // Basic string search for "exp" - simplified, consider robust JSON parsing
            String expClaimKey = "\"exp\":";
            int startIndex = payloadString.indexOf(expClaimKey);
            if (startIndex == -1) {
                // try finding without quotes around exp, just in case though standard is with
                // quotes
                expClaimKey = "exp:";
                startIndex = payloadString.indexOf(expClaimKey);
                if (startIndex == -1)
                    return null;
            }
            startIndex += expClaimKey.length();

            // Find the end of the number
            int endIndex = startIndex;
            while (endIndex < payloadString.length() && Character.isDigit(payloadString.charAt(endIndex))) {
                endIndex++;
            }

            if (startIndex == endIndex) { // No digits found
                log.warn("不安全的 EXP 擷取：未找到 EXP 數值。");
                return null;
            }

            String expValueString = payloadString.substring(startIndex, endIndex).trim();
            if (expValueString.isEmpty()) {
                log.warn("不安全的 EXP 擷取：EXP 數值字串為空。");
                return null;
            }

            long expMillis = Long.parseLong(expValueString) * 1000L; // JWT exp is in seconds, convert to milliseconds
            return new Date(expMillis);

        } catch (Exception e) { // NumberFormatException, IllegalArgumentException, etc.
            log.warn("不安全的 EXP 擷取：解析權杖 payload 取得 EXP 時發生錯誤。{}。Token 片段：{}",
                    e.getMessage(), token.substring(0, Math.min(token.length(), 20)));
            return null;
        }
    }

    /**
     * 檢查 JWT 權杖是否已過期。
     *
     * @param token JWT 權杖字串。
     * @return 如果權杖已過期，則返回 {@code true}；否則返回 {@code false}。
     *         如果無法確定過期時間 (例如，權杖無效或缺少過期聲明)，也返回 {@code true} (視為已過期)。
     * @throws JwtException             如果在解析權杖以獲取過期聲明時發生錯誤。
     * @throws IllegalArgumentException 如果權杖字串為 {@code null} 或空白。
     */
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getClaims(token).getExpiration();
            if (expiration == null) {
                log.warn("Token does not contain an expiration claim.");
                return true; // Treat as expired if no expiration claim
            }
            return expiration.before(new Date());
        } catch (JwtException e) {
            log.warn("Cannot determine token expiration due to parsing error: {}", e.getMessage());
            return true; // Treat as expired if token is invalid
        }
    }

    /**
     * 定期清理已失效且過期的 JTI。
     * <p>
     * 此方法使用 {@code @Scheduled} 註解來定期執行。執行頻率和緩衝時間可透過
     * {@link JwtConfigProperties} (對應於 application.yml 中的
     * {@code jwt.blacklist.cleanupFixedRateMs}
     * 和 {@code jwt.blacklist.cleanupBufferMs}) 進行配置。
     * </p>
     * <p>
     * 清理邏輯：
     * 遍歷儲存已失效 JTI 的映射 {@link #invalidatedJtisWithTimestamp}。
     * 如果一個 JTI 的原始 Token 過期時間加上配置的緩衝期小於當前時間，
     * 則將該 JTI 從映射中移除。
     * </p>
     */
    @Scheduled(fixedRateString = "${jwt.blacklist.cleanupFixedRateMs:3600000}", initialDelayString = "${jwt.blacklist.cleanupFixedRateMs:3600000}")
    public void cleanupInvalidatedJtis() {
        long currentTime = System.currentTimeMillis();
        long buffer = jwtConfigProperties.getBlacklist().getCleanupBufferMs(); // 從配置獲取緩衝期

        log.info("Running scheduled JTI cleanup task. Current invalidated JTI count: {}",
                invalidatedJtisWithTimestamp.size());

        // removedCount 變數已移除，因未被使用
        try {
            invalidatedJtisWithTimestamp.entrySet().removeIf(entry -> {
                boolean shouldRemove = (entry.getValue() + buffer) < currentTime;
                if (shouldRemove) {
                    log.trace("Scheduled for removal: JTI {} (expiry: {}, buffer: {}ms).",
                            entry.getKey(), new Date(entry.getValue()), buffer);
                }
                return shouldRemove;
            });
            // After removeIf, the map is modified. To get the count of removed items, we'd
            // need to compare size or count manually.
            // For simplicity, we'll log the state after. A more precise count would require
            // iterating and removing manually.
            // However, removeIf is generally more efficient.
        } catch (Exception e) {
            log.error("Error during JTI cleanup task: {}", e.getMessage(), e);
            // Depending on the error, you might want to handle it more gracefully
        }

        // It's hard to get exact removedCount with removeIf without re-iterating or
        // pre-counting.
        // Logging current size is more straightforward.
        log.info("Scheduled JTI cleanup task finished. Current invalidated JTI count after cleanup: {}",
                invalidatedJtisWithTimestamp.size());
    }

    /**
     * 提供對內部 JTI 黑名單 Map 的訪問，主要用於測試或監控。
     * **警告：** 不應在業務邏輯中直接修改此 Map。
     * 
     * @return JTI 黑名單的直接引用。
     */
    // For testing or monitoring purposes, if needed
    public Map<String, Long> getInvalidatedJtisWithTimestamp() {
        return invalidatedJtisWithTimestamp;
    }
}
