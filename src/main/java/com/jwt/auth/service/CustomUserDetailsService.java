package com.jwt.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link UserDetailsService} 的自訂實作。
 * <p>
 * 在基於 JWT 的身份驗證系統中，如果使用者角色和權限直接嵌入並從 JWT 本身進行驗證，
 * 此服務的角色可能會相對較輕。然而，Spring Security 的架構通常仍需要此服務的存在。
 * </p>
 * <p>
 * 此初始的簡化版本假設：如果傳入一個使用者名稱（在此上下文中為 JWT 中的 userId），
 * 則該使用者被視為有效（因為 JWT 應該已在上游被驗證）。
 * 它返回一個 {@link UserDetails} 物件，其中包含空密碼和空的權限列表，
 * 因為這些通常由 {@link com.jwt.auth.security.JwtAuthenticationFilter} 基於權杖聲明來處理。
 * </p>
 */
@Service
@Slf4j // Lombok: 自動生成日誌記錄器
public class CustomUserDetailsService implements UserDetailsService {

    /**
     * 根據使用者名稱（在此上下文中為從 JWT 提取的 userId）載入使用者特定資料。
     *
     * <p>如果 {@link com.jwt.auth.security.JwtAuthenticationFilter} 嘗試載入 {@code UserDetails}，
     * 或者如果安全框架的其他部分需要它，Spring Security 會呼叫此方法。
     * 在我們目前的設定中，{@code JwtAuthenticationFilter} 直接使用從權杖中獲取的權限來建構 {@code Authentication} 物件，
     * 因此此方法對於身份驗證流程本身可能不是嚴格必需的，但為了框架的完整性和未來的增強（例如，檢查帳戶狀態），
     * 擁有此實作是一個良好的實踐。</p>
     *
     * <p>此初始實作的細節：
     * <ul>
     *   <li>它假設使用者（由 {@code username}，即 JWT 中的 {@code userId} 標識）存在，
     *       因為 JWT 的驗證應該已經發生。</li>
     *   <li>它返回一個 {@link User} 物件，包含提供的使用者名稱、一個空密碼（因為在 JWT 驗證後認證中不使用密碼）
     *       以及一個空的權限列表（因為這些權限是直接從 {@link com.jwt.auth.security.JwtAuthenticationFilter}
     *       中的 JWT 聲明中派生的）。</li>
     *   <li>未來的增強可能涉及從資料庫中獲取實際的使用者詳細資訊（例如，帳戶狀態，如
     *       {@code isAccountNonExpired}, {@code isAccountNonLocked}, {@code isCredentialsNonExpired}, {@code isEnabled}）。</li>
     * </ul>
     * </p>
     *
     * @param username 需要其資料的使用者名稱（即從 JWT 中提取的 userId）。
     * @return 一個 {@link UserDetails} 物件 (永不為 {@code null})。
     * @throws UsernameNotFoundException 如果找不到使用者，或者使用者沒有任何 {@link GrantedAuthority}。
     *                                   在此簡化版本中，對於已硬編碼的現有使用者，不會拋出此異常。
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("CustomUserDetailsService: Attempting to load user by username (userId): {}", username);

        // In a real application, you would fetch user details from a database using the username (userId).
        // For example:
        // AppUser appUser = userRepository.findByUsername(username)
        //     .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        //
        // List<GrantedAuthority> authorities = appUser.getRoles().stream()
        //     .map(role -> new SimpleGrantedAuthority(role.getName()))
        //     .collect(Collectors.toList());
        //
        // return new User(appUser.getUsername(), appUser.getPassword(), appUser.isEnabled(),
        //                 appUser.isAccountNonExpired(), appUser.isCredentialsNonExpired(),
        //                 appUser.isAccountNonLocked(), authorities);

        // For this initial JWT-focused setup, where JwtAuthenticationFilter handles authority extraction
        // from the token, this UserDetailsService primarily fulfills the contract.
        // The authorities list can be empty here as it's populated in the filter.
        // The password is empty as it's not used for JWT validation.
        // If JwtAuthenticationFilter were to rely on UserDetailsService for authorities,
        // this method would need to fetch/assign them.

        // Hardcoded example users for completeness if directly queried (though filter usually bypasses this need for roles)
        if ("user".equals(username) || "admin".equals(username)) {
            // Authorities are set in JwtAuthenticationFilter from token.
            // If UserDetailsService was the source of truth for roles after token validation,
            // you would load them here.
            List<GrantedAuthority> authorities = new ArrayList<>();
            log.info("CustomUserDetailsService: User '{}' found (simulated). Authorities will be derived from token in filter.", username);
            return new User(username, "", true, true, true, true, authorities);
        } else {
            // This case should ideally not be hit if the JWT is valid and contains a known userId.
            // If it is hit, it implies a discrepancy or a direct call to UserDetailsService with an unknown user.
            log.warn("CustomUserDetailsService: User '{}' not found (simulated).", username);
            throw new UsernameNotFoundException("User not found: " + username);
        }
    }
}
