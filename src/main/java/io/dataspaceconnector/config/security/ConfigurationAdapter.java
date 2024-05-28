// /*
//  * Copyright 2020-2022 Fraunhofer Institute for Software and Systems Engineering
//  *
//  * Licensed under the Apache License, Version 2.0 (the "License");
//  * you may not use this file except in compliance with the License.
//  * You may obtain a copy of the License at
//  *
//  *    http://www.apache.org/licenses/LICENSE-2.0
//  *
//  * Unless required by applicable law or agreed to in writing, software
//  * distributed under the License is distributed on an "AS IS" BASIS,
//  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  * See the License for the specific language governing permissions and
//  * limitations under the License.
//  *
//  *  Contributors:
//  *       sovity GmbH
//  *
//  */
// package io.dataspaceconnector.config.security;

// import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
// import lombok.AccessLevel;
// import lombok.Getter;
// import lombok.extern.log4j.Log4j2;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.core.annotation.Order;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.security.web.SecurityFilterChain;

// /**
//  * This class configures admin rights for all backend endpoints behind "/api" using the role
//  * defined in {@link MultipleEntryPointsSecurityConfig}. If the web security is disabled, all
//  * DSC APIs are publicly available.
//  */
// @Log4j2
// @Configuration
// @Getter(AccessLevel.PUBLIC)
// @Order(2)
// public class ConfigurationAdapter {
//     /**
//      * Used name of admin role.
//      */
//     private static final String ADMIN = "ADMIN";

//     /**
//      * Whether the h2 console is enabled.
//      */
//     @Value("${spring.h2.console.enabled}")
//     private boolean h2Enabled;

//     /**
//      * Whether spring security DSC settings is enabled.
//      */
//     @Value("${spring.security.enabled}")
//     private boolean securityEnabled;

//     /**
//      * Gets the authenticationEntryPoint settings.
//      */
//     @Autowired
//     private AuthenticationEntryPoint authenticationEntryPoint;

//     /**
//      * Sets settings for spring security.
//      *
//      * @param http The HttpSecurity object.
//      * @return The extended SecurityFilterChain.
//      * @throws Exception If a setting or combination to be set is invalid.
//      */
//     @Bean
//     public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
//         if (securityEnabled) {
//             enableSecuritySettings(http);

//             if (h2Enabled) {
//                 disableFrameProtection(http);
//             } else {
//                 enableFrameProtection(http);
//             }
//         } else {
//             if (h2Enabled) {
//                 disableFrameProtection(http);
//             }

//             disableSecuritySettings(http);
//         }

//         return http.build();
//     }

//     @SuppressFBWarnings("SPRING_CSRF_PROTECTION_DISABLED")
//     private void disableSecuritySettings(final HttpSecurity http) throws Exception {
//         http.authorizeRequests().anyRequest().permitAll().and().csrf().disable();
//         http.headers().xssProtection().disable();
//         http.headers().frameOptions().disable();
//     }

//     private void enableFrameProtection(final HttpSecurity http) throws Exception {
//         http.headers().frameOptions().deny();
//     }

//     @SuppressFBWarnings("SPRING_CSRF_PROTECTION_DISABLED")
//     private void enableSecuritySettings(final HttpSecurity http) throws Exception {
//         http.sessionManagement()
//                 .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                 .and()
//                 .authorizeRequests()
//                 .antMatchers("/", "/api/ids/data").permitAll()
//                 .antMatchers("/api/subscriptions/**").authenticated()
//                 .antMatchers("/api/**").hasRole(ADMIN)
//                 .antMatchers("/actuator/**").hasRole(ADMIN)
//                 .antMatchers("/database/**").hasRole(ADMIN)
//                 .anyRequest().authenticated()
//                 .and()
//                 .csrf().disable()
//                 .httpBasic()
//                 .authenticationEntryPoint(authenticationEntryPoint);
//         http.headers().xssProtection();
//     }

//     private void disableFrameProtection(final HttpSecurity http) throws Exception {
//         http.headers().frameOptions().disable();
//         if (log.isWarnEnabled()) {
//             log.warn("H2 Console enabled. Disabling frame protection.");
//         }
//     }
// }
