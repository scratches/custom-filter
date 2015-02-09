package demo;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@EnableAutoConfiguration
@RestController
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@RequestMapping("/")
	public String home() {
		return "Hello World";
	}

	@Configuration
	@EnableResourceServer
	protected static class OAuth2ResourceConfig extends ResourceServerConfigurerAdapter {

		private CustomAuthenticator customFilter = new CustomAuthenticator();
		
		@Override
		public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
			resources.authenticationManager(customFilter);
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest().authenticated().and()
					.addFilterAfter(customFilter, AbstractPreAuthenticatedProcessingFilter.class);
		}

	}

	protected static class CustomAuthenticator extends OAuth2AuthenticationManager implements Filter {

		private static Log logger = LogFactory.getLog(CustomAuthenticator.class);

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			try {
				return super.authenticate(authentication);
			}
			catch (Exception e) {
				return new CustomAuthentication(authentication.getPrincipal(), authentication.getCredentials());
			}
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
				throws ServletException, IOException {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication instanceof CustomAuthentication) {
				CustomAuthentication custom = (CustomAuthentication) authentication;
				logger.info("Found custom authentication: " + custom.getPrincipal());
				if ("GOOD".equals(custom.getPrincipal())) {
					authentication.setAuthenticated(true);
				} else {
					SecurityContextHolder.clearContext();
				}
			}
			filterChain.doFilter(request, response);
		}

		@Override
		public void destroy() {
		}

		@Override
		public void init(FilterConfig arg0) throws ServletException {
		}

		@SuppressWarnings("serial")
		protected static class CustomAuthentication extends PreAuthenticatedAuthenticationToken {

			public CustomAuthentication(Object principal, Object credentials) {
				super(principal, credentials);
			}

		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.authenticationManager(authenticationManager);
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
		 	clients.inMemory()
		        .withClient("client")
		            .authorizedGrantTypes("password")
		            .authorities("ROLE_CLIENT")
		            .scopes("read", "write")
		            .resourceIds("oauth2-resource");
		 	// @formatter:on
		}

	}

}
