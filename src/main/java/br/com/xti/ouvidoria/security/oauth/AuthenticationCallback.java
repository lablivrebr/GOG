package br.com.xti.ouvidoria.security.oauth;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.primefaces.json.JSONObject;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.StoredCredential;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.extensions.servlet.auth.oauth2.AbstractAuthorizationCodeCallbackServlet;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;

import br.com.xti.ouvidoria.dao.UsuarioDAO;
import br.com.xti.ouvidoria.model.TbUsuario;

@WebServlet(urlPatterns = { "/oauth2Callback" })
public class AuthenticationCallback extends AbstractAuthorizationCodeCallbackServlet {

	@EJB
    private UsuarioDAO usuarioDAO;
	
	private static String CLIENT_ID;
	private static String CLIENT_SECRET;
	private static String CALLBACK_URI;
	private static String TOKEN_SERVER_URL;
	private static String AUTHORIZATION_SERVER_URL;
	private static Iterable<String> SCOPE;
	private static String USER_INFO_URL;
	
	private static JsonFactory JSON_FACTORY = new JacksonFactory();
	private static HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

	AuthorizationCodeFlow objAuthorizationCodeFlow = null;
	
	@Override
	public void init() throws ServletException {
		ServletContext context = getServletContext();
	    CLIENT_ID = context.getInitParameter("CLIENT_ID");
	    CLIENT_SECRET = context.getInitParameter("CLIENT_SECRET");
	    CALLBACK_URI = context.getInitParameter("CALLBACK_URI");
	    TOKEN_SERVER_URL = context.getInitParameter("TOKEN_SERVER_URL");
	    AUTHORIZATION_SERVER_URL = context.getInitParameter("AUTHORIZATION_SERVER_URL");
	    SCOPE = Arrays.asList(context.getInitParameter("SCOPE").split(";"));;
	    USER_INFO_URL = context.getInitParameter("USER_INFO_URL");
	    
		super.init();
	}

	@Override
	  protected void onSuccess(HttpServletRequest request, HttpServletResponse response, Credential credential)
	      throws ServletException, IOException {
		
		//PasswordUtils.getMD5("abcd123456").toUpperCase();
		
		try {
			HttpTransport transport = this.objAuthorizationCodeFlow.getTransport();
			HttpRequestFactory requestFactory = transport.createRequestFactory(credential);
			
			GenericUrl url = new GenericUrl(USER_INFO_URL);
			HttpRequest userInfoRequest = requestFactory.buildGetRequest(url);
			String userIdentity = userInfoRequest.execute().parseAsString();
			
			request.getSession().setAttribute("oauthUserIdentity", userIdentity);
			
			//String oauthUserIdentity = request.getSession().getAttribute("oauthUserIdentity").toString();
			
			JSONObject objJson = new JSONObject(userIdentity);
			String email = objJson.get("email").toString();
			String idOauth = objJson.get("id").toString();
			
			TbUsuario objTbUsuarioOauth = usuarioDAO.obterPorIdOauth(idOauth);
			TbUsuario objTbUsuarioEmail = usuarioDAO.findByEmail(email);
			
			if(objTbUsuarioEmail != null) {
				
				if(objTbUsuarioOauth == null) {
					objTbUsuarioEmail.setIdOauth(idOauth);
					usuarioDAO.edit(objTbUsuarioEmail);
				}
				
				request.login(objTbUsuarioEmail.getNmUsuario(), objTbUsuarioEmail.getNmSenha());
				response.sendRedirect("/GOG/pages/manifestacao/listarmanifestacoes.xhtml");
			} else if(objTbUsuarioOauth != null) {
				request.login(objTbUsuarioOauth.getNmUsuario(), objTbUsuarioOauth.getNmSenha());
				response.sendRedirect("/GOG/pages/manifestacao/listarmanifestacoes.xhtml");
			} else {
				request.setAttribute("nmUsuario", objJson.get("full_name").toString());
				request.setAttribute("nmLogin", objJson.get("username").toString());
				request.setAttribute("eeEmail", objJson.get("email").toString());
				
				RequestDispatcher dispatcher = request.getRequestDispatcher("/pages/externo/cadastrarManifestante.xhtml");
				dispatcher.forward(request, response);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	  }
	
	@Override
	protected void onError(HttpServletRequest req, HttpServletResponse resp, AuthorizationCodeResponseUrl errorResponse)
			throws ServletException, IOException {
		resp.sendRedirect("/GOG/pages/erro/erro.xhtml");
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
							.setCredentialDataStore(StoredCredential
							.getDefaultDataStore(new FileDataStoreFactory(new File("oauth2StorageFolder"))))
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
