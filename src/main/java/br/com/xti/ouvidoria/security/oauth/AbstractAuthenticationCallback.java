package br.com.xti.ouvidoria.security.oauth;

import java.io.IOException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;

abstract class AbstractAuthenticationCallback extends HttpServlet {

	private static final long serialVersionUID = 1L;

	  /** Lock on the flow. */
	  private final Lock lock = new ReentrantLock();

	  /**
	   * Authorization code flow to be used across all HTTP servlet requests or {@code null} before
	   * initialized in {@link #initializeFlow()}.
	   */
	  private AuthorizationCodeFlow flow;

	  @Override
	  protected final void doGet(HttpServletRequest req, HttpServletResponse resp)
	      throws ServletException, IOException {
	    StringBuffer buf = req.getRequestURL();
	    if (req.getQueryString() != null) {
	      buf.append('?').append(req.getQueryString());
	    }
	    AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(buf.toString());
	    String code = responseUrl.getCode();
	    if (responseUrl.getError() != null) {
	      onError(req, resp, responseUrl);
	    } else if (code == null) {
	      resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
	      resp.getWriter().print("Missing authorization code");
	    } else {
	      lock.lock();
	      try {
	        if (flow == null) {
	          flow = initializeFlow();
	        }
	        String redirectUri = getRedirectUri(req);
	        TokenResponse response = flow.newTokenRequest(code).setRedirectUri(redirectUri).execute();
	        String userId = getUserId(req);
	        Credential credential = flow.createAndStoreCredential(response, userId);
	        onSuccess(req, resp, credential);
	      } catch (Exception e) {
	    	  e.printStackTrace();
	      } finally {
	        lock.unlock();
	      }
	    }
	  }

	  protected abstract AuthorizationCodeFlow initializeFlow() throws ServletException, IOException;

	  protected abstract String getRedirectUri(HttpServletRequest req)
	      throws ServletException, IOException;

	  protected abstract String getUserId(HttpServletRequest req) throws ServletException, IOException;

	  protected void onSuccess(HttpServletRequest req, HttpServletResponse resp, Credential credential)
	      throws ServletException, IOException {
	  }

	  protected void onError(
	      HttpServletRequest req, HttpServletResponse resp, AuthorizationCodeResponseUrl errorResponse)
	      throws ServletException, IOException {
	  }
}
