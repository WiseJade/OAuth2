package com.codestates.oauth.config.auth;

import com.codestates.oauth.model.Member;
import com.codestates.oauth.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getClientId();
        String providerId = oAuth2User.getAttribute("sub");
        String username = oAuth2User.getAttribute("name");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        Member memberEntity = memberRepository.findByUsername(username);

        if(memberEntity == null) {
            // OAuth로 처음 로그인한 유저 - 회원가입 처리
            memberEntity = Member.builder()
                    .username(username)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            memberRepository.save(memberEntity);
        }

        System.out.println("userRequest: " + userRequest);
        return new PrincipalDetails(memberEntity, oAuth2User.getAttributes());
    }

}
