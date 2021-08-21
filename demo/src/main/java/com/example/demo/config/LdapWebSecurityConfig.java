package com.example.demo.config;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.Md4PasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

@EnableWebSecurity
public class LdapWebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${ldap.user.dn.pattern}")
  private String ldapUserDnPattern;

  @Value("${ldap.urls}")
  private String ldapUrls;

  @Value("${ldap.base.dn}")
  private String ldapBaseDn;

  @Value("${ldap.username}")
  private String ldapSecurityPrincipal;

  @Value("${ldap.password}")
  private String ldapPrincipalPassword;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
      .anyRequest()
      .fullyAuthenticated()
      .and()
      .formLogin();
  }

  @Override
  public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
      .ldapAuthentication()
      .userDnPatterns(ldapUserDnPattern)
      .groupSearchBase("ou=Users")
      .contextSource()
      .url(ldapUrls + ldapBaseDn)
      .managerDn(ldapSecurityPrincipal)
      .managerPassword(ldapPrincipalPassword)
      .and()
      .passwordCompare()
      .passwordEncoder(passwordEncoder())
      .passwordAttribute("userPassword");
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    String encodingId = "MD5";
    Map<String, PasswordEncoder> encoders = new HashMap<>();
    encoders.put(encodingId, new BCryptPasswordEncoder());
    encoders.put("ldap", new LdapShaPasswordEncoder());
    encoders.put("MD4", new Md4PasswordEncoder());
    encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
    encoders.put("noop", NoOpPasswordEncoder.getInstance());
    encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
    encoders.put("scrypt", new SCryptPasswordEncoder());
    encoders.put("SHA-1", new MessageDigestPasswordEncoder("SHA-1"));
    encoders.put("SHA-256", new MessageDigestPasswordEncoder("SHA-256"));
    encoders.put("sha256", new StandardPasswordEncoder());

    return new DelegatingPasswordEncoder(encodingId, encoders);
  }
}
