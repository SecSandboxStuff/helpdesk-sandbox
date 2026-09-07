package com.secsandbox.helpdesk;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Everything under /public/** is reachable with no authentication at all — that
 * is what makes the critical mutations on those routes CWE-306 rather than
 * CWE-862. The rest of the app requires a session; whether a given handler also
 * checks a role is what separates the CWE-862 findings from their safe twins.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}
