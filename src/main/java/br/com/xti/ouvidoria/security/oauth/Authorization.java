package br.com.xti.ouvidoria.security.oauth;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.extensions.servlet.auth.oauth2.AbstractAuthorizationCodeCallbackServlet;
import com.google.api.client.extensions.servlet.auth.oauth2.AbstractAuthorizationCodeServlet;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleOAuthConstants;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.store.FileDataStoreFactory;

import br.com.xti.ouvidoria.controller.MensagemFaceUtil;
import br.com.xti.ouvidoria.util.JSFUtils;

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson.JacksonFactory;

@WebServlet(urlPatterns = {"/oauth2Authorization" })
public class Authorization extends AbstractAuthorizationCodeServlet {
	
	private static final String CLIENT_ID = "11_4psf5i795ta8sow88gcco4sgkow0kcgcwggs4wog0g84ww8gow";
	private static final String CLIENT_SECRET = "14nampuvl98g08wwkg0k4cgsws4kwss8c080g00wc04og08cco";
	private static final String CALLBACK_URI = "http://gog.local.com.br:8080/GOG/oauth2Callback";
	private static final String TOKEN_SERVER_URL = "http://id.cultura.gov.br/oauth/v2/token";
	private static final String AUTHORIZATION_SERVER_URL = "http://id.cultura.gov.br/oauth/v2/auth";
	
	private static final Iterable<String> SCOPE = Arrays.asList("public_profile;cpf;email;full_name".split(";"));
	private static final String USER_INFO_URL = "http://id.cultura.gov.br/api/v1/person.json";
	private static final JsonFactory JSON_FACTORY = new JacksonFactory();
	private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
	
	private AuthorizationCodeFlow objAuthorizationCodeFlow;
	
	 @Override
	  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		 
		 if (request.getParameter("code") != null) {
			/*String user_info = this.getUserInfoJson(request.getParameter("code"));
			System.out.println(user_info);*/
		}
		 try {
			JSFUtils.redirect("/login");
		} catch (Exception e) {
			MensagemFaceUtil.erro("Erro ao redirecionar página de login", null);
		}
	  }
	 
	  @Override
	  protected String getRedirectUri(HttpServletRequest request) throws ServletException, IOException {
	    GenericUrl url = new GenericUrl(request.getRequestURL().toString());
	    url.setRawPath(request.getContextPath() + "/oauth2Callback");
	    return url.build();
	  }
	
	  @Override
	  protected AuthorizationCodeFlow initializeFlow() throws IOException {
		  objAuthorizationCodeFlow = new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
	        new NetHttpTransport(),
	        new JacksonFactory(),
	        new GenericUrl(TOKEN_SERVER_URL),
		    new BasicAuthentication(CLIENT_ID, CLIENT_SECRET),
		    CLIENT_ID,
		    AUTHORIZATION_SERVER_URL).setCredentialDataStore(StoredCredential.getDefaultDataStore(new FileDataStoreFactory(new File("datastoredir"))))
    		.setScopes((Collection<String>) SCOPE)
	        .build();
		  return objAuthorizationCodeFlow;
	  }
	
	  @Override
	  protected String getUserId(HttpServletRequest req) throws ServletException, IOException {
		  return CLIENT_ID;
	  }
/*
	  public String getUserInfoJson(final String authCode) throws TokenResponseException {
		String jsonIdentity = " "; 
		try {
			AuthorizationCodeTokenRequest objAuthorizationCodeTokenRequest = objAuthorizationCodeFlow.newTokenRequest(authCode);
			objAuthorizationCodeTokenRequest.setRedirectUri(CALLBACK_URI);
			TokenResponse response = objAuthorizationCodeTokenRequest.execute();
			final Credential credential = objAuthorizationCodeFlow.createAndStoreCredential(response, null);
			final HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(credential);
			// Make an authenticated request
			final GenericUrl url = new GenericUrl(USER_INFO_URL);
			final HttpRequest request = requestFactory.buildGetRequest(url);
			request.getHeaders().setContentType("application/json");
			jsonIdentity = request.execute().parseAsString();
		
			
		} catch (TokenResponseException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return jsonIdentity;
			
	  }	
	  */
}