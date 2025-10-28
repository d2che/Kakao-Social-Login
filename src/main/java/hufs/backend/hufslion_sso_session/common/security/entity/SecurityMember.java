package hufs.backend.hufslion_sso_session.common.security.entity;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import hufs.backend.hufslion_sso_session.member.entity.Member;
import lombok.Getter;

@Getter
public class SecurityMember implements UserDetails {

    private final Member member;

    public SecurityMember(Member member) {
        this.member = member;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new SimpleGrantedAuthority("USER"));
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getEmail();
    }

    public static SecurityMember from(Member member) {
        return new SecurityMember(member);
    }
}
