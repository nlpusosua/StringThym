1. User
   Ý nghĩa và chức năng:
   Đối tượng User đại diện cho người dùng trong hệ thống.

   Các method chính:
   - getUsername(): Lấy tên đăng nhập của người dùng.
   - getPassword(): Lấy mật khẩu của người dùng.
   - getAuthorities(): Lấy danh sách các quyền của người dùng.
Demo code đã có sẵn.

2. UserDetails
   Ý nghĩa và chức năng:
   UserDetails là một interface cung cấp các thông tin cần thiết cho xác thực người dùng.

   Các method chính:
   - getUsername()
   - getPassword()
   - getAuthorities()
   - isAccountNonExpired()
   - isAccountNonLocked()
   - isCredentialsNonExpired()
   - isEnabled()
Code demo:
(Đã trình bày ở trên trong phần User)

3. UserDetailsService
   Ý nghĩa và chức năng:
   UserDetailsService là một interface để tải thông tin người dùng dựa trên tên đăng nhập.

   Các method chính:
   loadUserByUsername(String username): Tải thông tin người dùng dựa trên tên đăng nhập.

   Code demo:

   import org.springframework.security.core.userdetails.UserDetails;
   import org.springframework.security.core.userdetails.UserDetailsService;
   import org.springframework.security.core.userdetails.UsernameNotFoundException;
   import java.util.ArrayList;

public class CustomUserDetailsService implements UserDetailsService {
@Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
// Logic to fetch user from database
if ("admin".equals(username)) {
return new CustomUser("admin", "password", new ArrayList<>());
} else {
throw new UsernameNotFoundException("User not found");
}
}
}

4. PasswordEncoder
   Ý nghĩa và chức năng:
   PasswordEncoder là một interface để mã hóa và kiểm tra mật khẩu.

   Các method chính:
   - encode(CharSequence rawPassword): Mã hóa mật khẩu gốc.
   - matches(CharSequence rawPassword, String encodedPassword): Kiểm tra mật khẩu gốc với mật khẩu đã mã hóa.

   Code demo:

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomPasswordEncoder implements PasswordEncoder {
private final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    @Override
    public String encode(CharSequence rawPassword) {
        return bCryptPasswordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
    }
}

5. AuthenticationProvider
   Ý nghĩa và chức năng:
   AuthenticationProvider là một interface để xác thực người dùng bằng cách kiểm tra thông tin đăng nhập.

   Các method chính:
   - authenticate(Authentication authentication): Xác thực người dùng.
   - supports(Class<?> authentication): Kiểm tra xem AuthenticationProvider này có hỗ trợ kiểu xác thực cụ thể hay không.

Code demo:

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {
private final UserDetailsService userDetailsService;
private final PasswordEncoder passwordEncoder;

    public CustomAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        UserDetails user = userDetailsService.loadUserByUsername(username);

        if (passwordEncoder.matches(password, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, user.getAuthorities());
        } else {
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}

6. SecurityContextHolder
   Ý nghĩa và chức năng:
   SecurityContextHolder là một class lưu trữ thông tin bảo mật của người dùng hiện tại, bao gồm thông tin xác thực và chi tiết người dùng.

   Các method chính:
   - getContext(): Lấy SecurityContext hiện tại.
   - setContext(SecurityContext context): Thiết lập SecurityContext hiện tại.
   - clearContext(): Xóa SecurityContext hiện tại.

Code demo:

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtils {
public static String getCurrentUsername() {
SecurityContext context = SecurityContextHolder.getContext();
Authentication authentication = context.getAuthentication();
if (authentication != null) {
return authentication.getName();
}
return null;
}
    public static void clearAuthentication() {
        SecurityContextHolder.clearContext();
    }
}

