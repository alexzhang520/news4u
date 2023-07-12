package com.fedex.apac.esd.common;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.event.LoggerListener;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.ldap.authentication.UserDetailsServiceLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import com.fedex.apac.esd.common.service.AuditService;
import com.fedex.apac.esd.common.service.UserService;
import com.fedex.apac.esd.common.service.security.CommonJdbcDaoImpl;
import com.fedex.apac.esd.common.service.security.oauth2.CustomClientRegistrations;
import com.fedex.apac.esd.common.service.security.oauth2.CustomOidcAuthorizationCodeAuthenticationProvider;
import com.fedex.apac.esd.common.service.security.oauth2.CustomOidcClientInitiatedLogoutSuccessHandler;
import com.fedex.apac.esd.common.util.config.service.impl.ConfigurationImpl;
import com.fedex.apac.esd.common.web.filter.CustomAuthenticationProcessingFilter;
import com.fedex.apac.esd.common.web.filter.ECSecurityFilter;
import com.fedex.apac.esd.common.web.filter.FileDownloadProcessFilter;
import com.fedex.apac.esd.common.web.filter.LDAPProcessFilter;
import com.fedex.apac.esd.common.web.filter.PasswordExpiredFilter;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackages = { "com.fedex.apac.esd.common.service.security", "com.fedex.apac.esd.common.web.filter" })
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	private static final Log logger = LogFactory.getLog(SecurityConfig.class);
	
  @Autowired
  private Environment env;
  private Properties properties;
  private boolean ssoEnabled = false;
    
  @Override
  public void configure(WebSecurity web) throws Exception {
    // @formatter:off
    web
      .ignoring()
        .antMatchers(
            "/common/css/**",
            "/xmlhttp/css/**",
            "/common/images/**",
            "/common/includes/**",
            "/common/js/**",
            "/xmlhttp/**",
            "/login*",
            "/accountExpired*",
            "/accountLocked*",
            "/credentialsExpired*",
            "/timeout*",
            "/notFound*",
            "/serverError*",
            "/oss/*",
            "/ossNotice*",
            "/systemstatus.*",
            "/webservices/**",
            "/webservice/**",
            "/javax.faces.resource/**",
            "/barcode/**",
            "/index*",
            "/"
        );
    // @formatter:on
  }
  
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // @formatter:off 
	loadProperties();
	ssoEnabled = "true".equalsIgnoreCase(properties.getProperty("okta.oauth2.pkce"));
	
	if (ssoEnabled) {
		http.oauth2Login(oauth2Login -> oauth2Login
		  .clientRegistrationRepository(clientRegistrationRepository())
		  .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.baseUri(properties.getProperty("okta.oauth2.authorization-base-uri")))
		  .tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenResponseClient(accessTokenResponseClient()))
		  .redirectionEndpoint(redirectionEndpoint -> redirectionEndpoint.baseUri(properties.getProperty("okta.oauth2.redirect-base-uri")))
		  .defaultSuccessUrl("/")
		)
		.authenticationProvider(authenticationProvider());
	}
	
	http.headers(headers -> headers
          .frameOptions(frameOptions -> frameOptions
              .sameOrigin().contentSecurityPolicy(contentSecurityPolicy -> contentSecurityPolicy
                      .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"))
          )
      )
      .csrf(csrf -> csrf.disable())
      .authorizeRequests(authorize -> authorize
              .antMatchers("/shipping/**")
              .fullyAuthenticated()
              .antMatchers("/common/**")
                .fullyAuthenticated()
              .antMatchers("/reporting/**")
                .fullyAuthenticated())
        .exceptionHandling()
          .accessDeniedPage("/accessDenied.html")
      .and()
        .formLogin()
          .loginProcessingUrl("/j_spring_security_check")
          .loginPage("/timeout.html")
          .usernameParameter("j_username")
          .passwordParameter("j_password")
          .failureUrl("/loginFailed.html")
          .defaultSuccessUrl("/common/commonHome.jsf", true)
      .and()
        .logout()
          .invalidateHttpSession(true)
          .logoutSuccessUrl("/")
          .logoutUrl("/j_spring_security_logout")
          .deleteCookies("JSESSIONID")
          .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository()))
      .and()
//        .addFilterAt(ldapFilter(), X509AuthenticationFilter.class)
        .addFilterAt(formFilter(), AbstractPreAuthenticatedProcessingFilter.class)
        .addFilterAt(fileDownloadFilter(), BasicAuthenticationFilter.class)
        .addFilterAfter(wssoFilter(), ExceptionTranslationFilter.class)
        .addFilterBefore(ecSecurityFilter(), FilterSecurityInterceptor.class)
        .addFilterAfter(passwordExpiredFilter(), SwitchUserFilter.class)
      .sessionManagement()
        .maximumSessions(1)
        .sessionRegistry(sessionRegistry())
        .expiredUrl("/timeout.html")
        .and()
        .sessionFixation()
          .newSession();
	
	if (!ssoEnabled) {
		http.addFilterAt(ldapFilter(), X509AuthenticationFilter.class);	
	}
    // @formatter:on
  }

  @Bean  
  public AuthenticationProvider authenticationProvider() {
	return new CustomOidcAuthorizationCodeAuthenticationProvider(accessTokenResponseClient(), oidcUserService(), properties);
}
  
  @Bean  
  public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {  
      DefaultOAuth2UserService userService = new DefaultOAuth2UserService();  
      userService.setRestOperations(oauth2ClientRestOperations());  
      return userService;  
  } 
  
  @Bean  
  public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {  
      OidcUserService userService = new OidcUserService();
      userService.setOauth2UserService(oauth2UserService());
      return userService;  
  }  
  
@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter(), new MappingJackson2HttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		
		DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		accessTokenResponseClient.setRestOperations(oauth2ClientRestOperations());
		return accessTokenResponseClient;
	}
  
  @Bean
	public RestOperations oauth2ClientRestOperations() {
		// Minimum required configuration
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(
				new FormHttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter(), 
				new MappingJackson2HttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

		// Add custom configuration, eg. Proxy, TLS, etc
		SimpleClientHttpRequestFactory requestFactory = CustomClientRegistrations.getRequestFactory(properties);
		if (requestFactory != null) {
			restTemplate.setRequestFactory(requestFactory);
		}
		return restTemplate;
	}
  
  @Bean(name="oauth2ClientIdTokenRestOperations")
	public RestOperations oauth2ClientIdTokenRestOperations() {
		// Minimum required configuration
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

		// Add custom configuration, eg. Proxy, TLS, etc
		SimpleClientHttpRequestFactory requestFactory = CustomClientRegistrations.getRequestFactory(properties);
		if (requestFactory != null) {
			restTemplate.setRequestFactory(requestFactory);
		}
		return restTemplate;
	}  

  @Bean
  public AuthenticationManager authenticationManager() {
    // @formatter:off
    return new ProviderManager(new AuthenticationProvider[] {
        (AuthenticationProvider) getApplicationContext().getBean("daoAuthenticationProvider"),
        (AuthenticationProvider) getApplicationContext().getBean("preauthAuthProvider")
    });
    // @formatter:on
  }

  @Bean
  public AuthenticationManager _authenticationManager() {
    // @formatter:off
    return new ProviderManager(new AuthenticationProvider[] {
        (AuthenticationProvider) getApplicationContext().getBean("preauthAuthProvider")
    });
    // @formatter:on
  }

  @Bean
  public AuthenticationManager authenticationManagerFclLdap() {
    // @formatter:off
	return new ProviderManager(new AuthenticationProvider[] {
		(AuthenticationProvider) getApplicationContext().getBean("ldapAuthProvider"),
		(AuthenticationProvider) getApplicationContext().getBean("fclAuthProvider") 
	});
    // @formatter:on
  }

  @Bean
  public AuthenticationManager authenticationManagerforDownload() {
    // @formatter:off
	return new ProviderManager(new AuthenticationProvider[] {
		(AuthenticationProvider) getApplicationContext().getBean("daoAuthenticationProvider"),
		(AuthenticationProvider) getApplicationContext().getBean("preauthAuthProvider"),
		(AuthenticationProvider) getApplicationContext().getBean("ldapAuthProvider") 
	});
    // @formatter:on
  }

  @Bean
  public AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> userDetailsServiceWrapper() {
    UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> bean = new UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>();
    bean.setUserDetailsService(wssoAuthenticationDao());

    return bean;
  }

  @Bean
  public UserDetailsService formAuthenticationDao() {
    // @formatter:off
    CommonJdbcDaoImpl bean = new CommonJdbcDaoImpl();
    bean.setDataSource((DataSource) getApplicationContext().getBean("dataSourceCommon"));
    bean.setEnableGroups(true);
    bean.setEnableAuthorities(false);
    bean.setUsersByUsernameQuery("SELECT USER_NM, PASSWORD_DESC, ENABLE_FLG, UNLOCK_TMSTP, PASSWORD_EXPIRY_DT FROM CM_USER WHERE USER_NM = ? AND IS_WSSO_FLG=0");
    bean.setGroupAuthoritiesByUsernameQuery("Select GAM.ACCOUNT_NBR,USR.GROUP_NBR, 'ROLE' ||'_'|| ROLE.ROLE_NM FROM CM_USER USR left join CM_GROUP_ROLE_MAP GrM on grm.group_nbr = usr.group_nbr left join CM_GROUP_ACCOUNT_MAP GAM on GAM.GROUP_NBR = usr.GROUP_NBR and GAM.Account_NBR=USR.DEFAULT_ACCOUNT_NBR left join CM_ROLE ROLE on  ROLE.Nbr = coalesce(GAM.role_nbr, GRM.role_nbr) WHERE USR.USER_NM = ? Order by GAM.ACCOUNT_NBR");

    return bean;
    // @formatter:on
  }

  @Bean
  public UserDetailsService fclAuthenticationDao() {
    // @formatter:off
    JdbcDaoImpl bean = new JdbcDaoImpl();
    bean.setDataSource((DataSource) getApplicationContext().getBean("dataSourceCommon"));
    bean.setEnableGroups(true);
    bean.setEnableAuthorities(false);
    bean.setUsersByUsernameQuery("SELECT USER_NM, 'PASSWORD_DESC' as PASSWORD_DESC, ENABLE_FLG FROM CM_USER WHERE USER_NM = ? AND IS_WSSO_FLG=1");
    bean.setGroupAuthoritiesByUsernameQuery("Select GAM.ACCOUNT_NBR,USR.GROUP_NBR, 'ROLE' ||'_'|| ROLE.ROLE_NM FROM CM_USER USR left join CM_GROUP_ROLE_MAP GrM on grm.group_nbr = usr.group_nbr left join CM_GROUP_ACCOUNT_MAP GAM on GAM.GROUP_NBR = usr.GROUP_NBR and GAM.Account_NBR=USR.DEFAULT_ACCOUNT_NBR left join CM_ROLE ROLE on  ROLE.Nbr = coalesce(GAM.role_nbr, GRM.role_nbr) WHERE USR.USER_NM = ? Order by GAM.ACCOUNT_NBR");

    return bean;
    // @formatter:on
  }

  @Bean
  public UserDetailsService ldapAuthenticationDao() {
    // @formatter:off
    JdbcDaoImpl bean = new JdbcDaoImpl();
    bean.setDataSource((DataSource) getApplicationContext().getBean("dataSourceCommon"));
    bean.setEnableGroups(true);
    bean.setEnableAuthorities(false);
    bean.setUsersByUsernameQuery("SELECT USER_NM, PASSWORD_DESC, ENABLE_FLG FROM CM_USER WHERE USER_NM = ? AND ENABLE_FLG = 1 AND IS_WSSO_FLG=1");
    bean.setGroupAuthoritiesByUsernameQuery("Select GAM.ACCOUNT_NBR,USR.GROUP_NBR, 'ROLE' ||'_'|| ROLE.ROLE_NM FROM CM_USER USR left join CM_GROUP_ROLE_MAP GrM on grm.group_nbr = usr.group_nbr left join CM_GROUP_ACCOUNT_MAP GAM on GAM.GROUP_NBR = usr.GROUP_NBR and GAM.Account_NBR=USR.DEFAULT_ACCOUNT_NBR left join CM_ROLE ROLE on  ROLE.Nbr = coalesce(GAM.role_nbr, GRM.role_nbr) WHERE USR.USER_NM = ? AND ENABLE_FLG = 1 Order by GAM.ACCOUNT_NBR");

    return bean;
    // @formatter:on
  }

  @Bean
  public UserDetailsService wssoAuthenticationDao() {
    // @formatter:off
    JdbcDaoImpl bean = new JdbcDaoImpl();
    bean.setDataSource((DataSource) getApplicationContext().getBean("dataSourceCommon"));
    bean.setEnableGroups(true);
    bean.setEnableAuthorities(false);
    bean.setUsersByUsernameQuery("SELECT USER_NM, PASSWORD_DESC, ENABLE_FLG FROM CM_USER WHERE USER_NM = ? AND IS_WSSO_FLG=1");
    bean.setGroupAuthoritiesByUsernameQuery("Select GAM.ACCOUNT_NBR,USR.GROUP_NBR, 'ROLE' ||'_'|| ROLE.ROLE_NM FROM CM_USER USR left join CM_GROUP_ROLE_MAP GrM on grm.group_nbr = usr.group_nbr left join CM_GROUP_ACCOUNT_MAP GAM on GAM.GROUP_NBR = usr.GROUP_NBR and GAM.Account_NBR=USR.DEFAULT_ACCOUNT_NBR left join CM_ROLE ROLE on  ROLE.Nbr = coalesce(GAM.role_nbr, GRM.role_nbr) WHERE USR.USER_NM = ? Order by GAM.ACCOUNT_NBR");

    return bean;
    // @formatter:on
  }

  @Bean
  public SessionAuthenticationStrategy sas() {
    List<SessionAuthenticationStrategy> delegateStrategies = new ArrayList<>();
    SessionFixationProtectionStrategy defaultSessionAuthenticationStrategy = new SessionFixationProtectionStrategy();
    defaultSessionAuthenticationStrategy.setMigrateSessionAttributes(false);
    defaultSessionAuthenticationStrategy.setAlwaysCreateSession(true);

    ConcurrentSessionControlAuthenticationStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlAuthenticationStrategy(
        sessionRegistry());
    concurrentSessionControlStrategy.setMaximumSessions(1);
//    concurrentSessionControlStrategy.setExceptionIfMaximumExceeded(true);

    RegisterSessionAuthenticationStrategy registerSessionStrategy = new RegisterSessionAuthenticationStrategy(
        sessionRegistry());

    delegateStrategies.addAll(
        Arrays.asList(concurrentSessionControlStrategy, defaultSessionAuthenticationStrategy, registerSessionStrategy));

    return new CompositeSessionAuthenticationStrategy(delegateStrategies);
  }

  @Bean
  public AuthenticationSuccessHandler fclAuthenticationSuccessHandler() {
    SavedRequestAwareAuthenticationSuccessHandler bean = new SavedRequestAwareAuthenticationSuccessHandler();
    bean.setAlwaysUseDefaultTargetUrl(true);
    bean.setDefaultTargetUrl("/" + env.getProperty("auth.fcl.default.target.url"));

    return bean;
  }

  @Bean
  public AuthenticationSuccessHandler fileDownloadAuthenticationSuccessHandler() {
    SavedRequestAwareAuthenticationSuccessHandler bean = new SavedRequestAwareAuthenticationSuccessHandler();
    bean.setAlwaysUseDefaultTargetUrl(true);
    bean.setDefaultTargetUrl("/" + env.getProperty("auth.download.default.target.url"));

    return bean;
  }

  @Bean
  public AuthenticationFailureHandler ldapAuthenticationFailureHandler() {
    // @formatter:off
    ExceptionMappingAuthenticationFailureHandler bean = new ExceptionMappingAuthenticationFailureHandler();
    bean.setDefaultFailureUrl("/" + env.getProperty("auth.ldap.authentication.failure.url"));

    Map<String, String> failureUrlMap = new HashMap<String, String>();
    failureUrlMap.put("org.springframework.security.authentication.CredentialsExpiredException", "/" + env.getProperty("auth.form.authentication.failure.credentials"));
    failureUrlMap.put("org.springframework.security.authentication.AccountExpiredException", "/" + env.getProperty("auth.form.authentication.failure.expired"));
    failureUrlMap.put("org.springframework.security.authentication.LockedException", "/" + env.getProperty("auth.form.authentication.failure.locked"));
    bean.setExceptionMappings(failureUrlMap);

    return bean;
    // @formatter:on
  }

  @Bean
  public AuthenticationFailureHandler formAuthenticationFailureHandler() {
    // @formatter:off
    ExceptionMappingAuthenticationFailureHandler bean = new ExceptionMappingAuthenticationFailureHandler();
    bean.setDefaultFailureUrl("/" + env.getProperty("auth.form.authentication.failure.url"));

    Map<String, String> failureUrlMap = new HashMap<String, String>();
    failureUrlMap.put("org.springframework.security.authentication.CredentialsExpiredException", "/" + env.getProperty("auth.form.authentication.failure.credentials"));
    failureUrlMap.put("org.springframework.security.authentication.AccountExpiredException", "/" + env.getProperty("auth.form.authentication.failure.expired"));
    failureUrlMap.put("org.springframework.security.authentication.LockedException", "/" + env.getProperty("auth.form.authentication.failure.locked"));
    bean.setExceptionMappings(failureUrlMap);

    return bean;
    // @formatter:on
  }

  @Bean
  public AuthenticationFailureHandler fclAuthenticationFailureHandler() {
    return new SimpleUrlAuthenticationFailureHandler("/" + env.getProperty("auth.fcl.authentication.failure.url"));
  }

  @Bean
  public AuthenticationFailureHandler fileDownloadAuthenticationFailureHandler() {
    return new SimpleUrlAuthenticationFailureHandler("/" + env.getProperty("auth.download.authentication.failure.url"));
  }

  @Bean
  public LdapAuthoritiesPopulator authoritiesPopulator() {
    return new UserDetailsServiceLdapAuthoritiesPopulator(ldapAuthenticationDao());
  }

  @Bean
  public PreAuthenticatedAuthenticationProvider preauthAuthProvider() {
    PreAuthenticatedAuthenticationProvider bean = new PreAuthenticatedAuthenticationProvider();
    bean.setPreAuthenticatedUserDetailsService(userDetailsServiceWrapper());

    return bean;
  }

  public LDAPProcessFilter ldapFilter() {
    // @formatter:off
    LDAPProcessFilter ldapFilter = new LDAPProcessFilter(
        "/" + env.getProperty("auth.ldap.filter.processes.url"),
        authenticationManagerFclLdap(),
        (AuthenticationSuccessHandler) getApplicationContext().getBean("urlResolver"),
        sas(),
        ldapAuthenticationFailureHandler()
    );
    ldapFilter.setLoginLdapEnabled(env.getProperty("auth.ldap.login.enabled"));
    ldapFilter.setUserLdapPrefix(env.getProperty("auth.ldap.user.prefix"));
    ldapFilter.setRequestPrincipal(env.getProperty("auth.ldap.request.principal"));
    ldapFilter.setRequestCredentials(env.getProperty("auth.ldap.request.credentials"));

    ldapFilter.setUserService((UserService) getApplicationContext().getBean("userService"));
    ldapFilter.setConfiguration((com.fedex.apac.esd.common.util.config.service.Configuration) getApplicationContext().getBean("configuration"));
    ldapFilter.setAuditService((AuditService) getApplicationContext().getBean("auditService"));

    return ldapFilter;
    // @formatter:on
  }

  public CustomAuthenticationProcessingFilter formFilter() {
    // @formatter:off
    CustomAuthenticationProcessingFilter formFilter = new CustomAuthenticationProcessingFilter(
        authenticationManager(),
        "/" + env.getProperty("auth.form.filter.processes.url"),
        (AuthenticationSuccessHandler) getApplicationContext().getBean("urlResolver"),
        sas(),
        formAuthenticationFailureHandler()
    );

    return formFilter;
    // @formatter:on
  }

  public FileDownloadProcessFilter fileDownloadFilter() {
    // @formatter:off
    FileDownloadProcessFilter fileDownloadFilter = new FileDownloadProcessFilter(
        "/" + env.getProperty("auth.download.filter.processes.url"),
        fileDownloadAuthenticationSuccessHandler(),
        fileDownloadAuthenticationFailureHandler(),
        authenticationManagerforDownload()
    );
    fileDownloadFilter.setRequestPrincipal(env.getProperty("auth.ldap.request.principal"));
    fileDownloadFilter.setRequestCredentials(env.getProperty("auth.ldap.request.credentials"));
    fileDownloadFilter.setUserService((UserService) getApplicationContext().getBean("userService"));
    fileDownloadFilter.setAuditService((AuditService) getApplicationContext().getBean("auditService"));
    fileDownloadFilter.setConfiguration((com.fedex.apac.esd.common.util.config.service.Configuration) getApplicationContext().getBean("configuration"));

    return fileDownloadFilter;
    // @formatter:on
  }

  public RequestHeaderAuthenticationFilter wssoFilter() {
    RequestHeaderAuthenticationFilter wssoFilter = new RequestHeaderAuthenticationFilter();
    wssoFilter.setPrincipalRequestHeader("OBLIX_UID");
    wssoFilter.setAuthenticationManager(authenticationManager());

    return wssoFilter;
  }

  public ECSecurityFilter ecSecurityFilter() {
    // @formatter:off
    ECSecurityFilter ecSecurityFilter = new ECSecurityFilter(
        authenticationManager(),
        (AccessDecisionManager) getApplicationContext().getBean("ecAccessDecisionManager"),
        (FilterInvocationSecurityMetadataSource) getApplicationContext().getBean("ecSecurityMetadataSource")
    );

    return ecSecurityFilter;
    // @formatter:on
  }

  public PasswordExpiredFilter passwordExpiredFilter() {
    PasswordExpiredFilter passwordExpiredFilter = new PasswordExpiredFilter();
    passwordExpiredFilter.setChangePasswordUrl(env.getProperty("auth.form.default.changepassword.url"));

    return passwordExpiredFilter;
  }

  @Bean
  public LoggerListener loggerListener() {
    return new LoggerListener();
  }

  @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public Pbkdf2PasswordEncoder pbkdf2PasswordEncoder() {
    return new Pbkdf2PasswordEncoder();
  }

  @Bean
  public SCryptPasswordEncoder sCryptPasswordEncoder() {
    return new SCryptPasswordEncoder();
  }

  @Bean
  public MessageDigestPasswordEncoder shaPasswordEncoder() {
    return new MessageDigestPasswordEncoder("SHA-256");
  }

  @Bean
  public Argon2PasswordEncoder argon2PasswordEncoder() {
    return new Argon2PasswordEncoder();
  }

  @Bean
  public DelegatingPasswordEncoder passwordEncoder() {
    Map<String, PasswordEncoder> idToPasswordEncoder = new HashMap<String, PasswordEncoder>();
    idToPasswordEncoder.put("bcrypt", bCryptPasswordEncoder());
    idToPasswordEncoder.put("pbkdf2", pbkdf2PasswordEncoder());
    idToPasswordEncoder.put("scrypt", sCryptPasswordEncoder());
    idToPasswordEncoder.put("SHA-256", shaPasswordEncoder());
    idToPasswordEncoder.put("argon2", argon2PasswordEncoder());

    DelegatingPasswordEncoder bean = new DelegatingPasswordEncoder("bcrypt", idToPasswordEncoder);
    bean.setDefaultPasswordEncoderForMatches(shaPasswordEncoder());

    return bean;
  }

  @Bean
  public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
  }

  @Bean
  public SessionRegistry sessionRegistry() {
    return new SessionRegistryImpl();
  }

  /**
   * Creates an customized OKTA client registration repository.
   * 
   * @return
   */
  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
	return new InMemoryClientRegistrationRepository(this.oktaClientRegistration());
  }
  
  /**
   * Builds an OKTA client registration. 
   * @return
   */
	private ClientRegistration oktaClientRegistration() {
		loadProperties();

		return CustomClientRegistrations.fromOidcIssuerLocation(properties.getProperty("okta.oauth2.issuer"), properties)
				.clientId(properties.getProperty("okta.oauth2.client-id"))
				.scope(properties.getProperty("okta.oauth2.scopes"))
				.redirectUriTemplate(properties.getProperty("okta.oauth2.redirect-uri"))
				.build();
	}
  
  /**
   * Creates an customized OKTA OIDC logout success handler.
   * 
   * @param clientRegistrationRepository
   * @return
   */
	private CustomOidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(
			ClientRegistrationRepository clientRegistrationRepository) {
		CustomOidcClientInitiatedLogoutSuccessHandler successHandler = new CustomOidcClientInitiatedLogoutSuccessHandler(
				clientRegistrationRepository);
		successHandler.setPostLogoutRedirectUri(properties.getProperty("okta.oauth2.post-logout-redirect-uri"));
		return successHandler;
	}
	
	/**
	 * Loads OKTA configuration properties from config_common.properties or config_application.properties or config_env.properties as OKTA
	 * configuration which cannot be retrieved from existing spring boot environment upon instantiating customized OKTA customized client
	 * registration repository.
	 * 
	 * @return
	 */
	private void loadProperties() {
		if (properties == null) {
			this.properties = new Properties();
			ConfigurationImpl bean = new ConfigurationImpl();
			
			bean.setIgnoreResourceNotFound(true);
			
			bean.setSystemPropertiesModeName("SYSTEM_PROPERTIES_MODE_OVERRIDE");

			bean.setLocations(new Resource[] { new ClassPathResource("config_common.properties"),
					new ClassPathResource("config_application.properties") });
			try {
				bean.loadProperties(properties);
				properties = bean.getProperties();
				
				String configPath = "/opt/fedex/shipping/properties/config_env.properties";
				if (new File(configPath).exists()) {
					
					properties.load(resource.getInputStream());
				}
				bean.setIgnoreUnresolvablePlaceholders(true);
				bean.setIgnoreResourceNotFound(true);
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
		}
	}
}
