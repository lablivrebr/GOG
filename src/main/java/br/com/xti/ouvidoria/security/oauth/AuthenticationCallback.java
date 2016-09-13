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
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
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
import br.com.xti.ouvidoria.util.PasswordUtils;

import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson.JacksonFactory;

@WebServlet(urlPatterns = { "/oauth2Callback" })
public class AuthenticationCallback extends AbstractAuthorizationCodeCallbackServlet {

	private static final String CLIENT_ID = "11_4psf5i795ta8sow88gcco4sgkow0kcgcwggs4wog0g84ww8gow";
	private static final String CLIENT_SECRET = "14nampuvl98g08wwkg0k4cgsws4kwss8c080g00wc04og08cco";
	private static final String CALLBACK_URI = "/oauth2Callback";
	private static final String TOKEN_SERVER_URL = "http://id.cultura.gov.br/oauth/v2/token";
	private static final String AUTHORIZATION_SERVER_URL = "http://id.cultura.gov.br/oauth/v2/auth";

	private static final Iterable<String> SCOPE = Arrays.asList("public_profile;cpf;email;full_name".split(";"));
	private static final String USER_INFO_URL = "http://id.cultura.gov.br/api/v1/person.json";
	private static final JsonFactory JSON_FACTORY = new JacksonFactory();
	private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
	
	AuthorizationCodeFlow objAuthorizationCodeFlow = null;

	@Override
	  protected void onSuccess(HttpServletRequest request, HttpServletResponse response, Credential credential)
	      throws ServletException, IOException {
		
		// 1 - Verificar se ja existe um usuário cadastrado com os dados vindos da credetial;
		// 1. 1 - Se já existir, verificar se a coluna "hasOauthPermission" está preenchida
		// 1. 2 - Caso não existir, redirecionar para o cadastro de um novo usuário utilizando as informações já existentes para completar o cadastro e preencher a coluna "hasOauthPermission"
		
		// senha padrão "PasswordUtils.getMD5(password).toUpperCase()"
		
		//PasswordUtils.getMD5("abcd123456").toUpperCase();
		
		// Verificar permissões
		//objAuthorizationCodeFlow.
		request.login("root", "123456");
		
	    response.sendRedirect("/GOG/pages/manifestacao/listarmanifestacoes.xhtml");
	  }

	@Override
	protected void onError(HttpServletRequest req, HttpServletResponse resp, AuthorizationCodeResponseUrl errorResponse)
			throws ServletException, IOException {
		resp.sendRedirect("/GOG/sniff...");
	}

	@Override
	protected String getRedirectUri(HttpServletRequest request) throws ServletException, IOException {
		GenericUrl url = new GenericUrl(request.getRequestURL().toString());
		url.setRawPath(request.getContextPath() + CALLBACK_URI);
		return url.build();
	}

	@Override
	protected AuthorizationCodeFlow initializeFlow() throws IOException {
		
		try {

			objAuthorizationCodeFlow = new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
					new NetHttpTransport(), new JacksonFactory(), new GenericUrl(TOKEN_SERVER_URL),
					new BasicAuthentication(CLIENT_ID, CLIENT_SECRET), CLIENT_ID, AUTHORIZATION_SERVER_URL)
					.setCredentialDataStore(StoredCredential.getDefaultDataStore(new FileDataStoreFactory(new File("oauth2StorageFolder"))))
					.setScopes((Collection<String>) SCOPE).build();
		} catch (TokenResponseException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return objAuthorizationCodeFlow;
	}

	@Override
	protected String getUserId(HttpServletRequest req) throws ServletException, IOException {
		return CLIENT_ID;
	}
}
