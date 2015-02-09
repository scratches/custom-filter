package demo;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
@WebAppConfiguration
@IntegrationTest("server.port=0")
public class ApplicationTests {

	@Value("${local.server.port}")
	private int port;

	private OAuth2RestTemplate restTemplate;

	@Before
	public void init() {
		ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();
		resource.setClientId("client");
		resource.setPassword("password");
		resource.setUsername("user");
		resource.setAccessTokenUri("http://localhost:" + port + "/oauth/token");
		restTemplate = new OAuth2RestTemplate(resource);
		restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
	}

	@Test
	public void protectedResource() {
		assertEquals(HttpStatus.UNAUTHORIZED,
				new TestRestTemplate().getForEntity("http://localhost:" + port, String.class).getStatusCode());
	}

	@Test
	public void accessResourceWithToken() {
		assertEquals("Hello World", restTemplate.getForEntity("http://localhost:" + port, String.class).getBody());
	}

	@Test
	public void accessResourceWithGoodToken() {
		restTemplate.getOAuth2ClientContext().setAccessToken(new DefaultOAuth2AccessToken("GOOD"));
		assertEquals("Hello World", restTemplate.getForEntity("http://localhost:" + port, String.class).getBody());
	}

	@Test(expected=OAuth2Exception.class)
	public void accessResourceWithCrapToken() {
		restTemplate.getOAuth2ClientContext().setAccessToken(new DefaultOAuth2AccessToken("CRAP"));
		assertEquals(HttpStatus.UNAUTHORIZED, restTemplate.getForEntity("http://localhost:" + port, String.class)
				.getStatusCode());
	}

}
