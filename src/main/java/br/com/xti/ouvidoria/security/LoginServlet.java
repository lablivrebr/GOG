package br.com.xti.ouvidoria.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.hibernate.validator.constraints.URL;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.CredentialRefreshListener;

import br.com.xti.ouvidoria.helper.ValidacaoHelper;
import br.com.xti.ouvidoria.model.TbManifestacao;
import br.com.xti.ouvidoria.security.oauth.Authorization;

@WebServlet(description = "Servlet responsável por efetuar o login do usuário", urlPatterns = { "/login" })
public class LoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final String LOGGED_INDEX_PAGE = "/pages/manifestacao/listarmanifestacoes.xhtml";
	private static final String MANIFESTATION_DETAIL_PAGE = "/pages/manifestacao/administrar.xhtml?num=%s&id=%s";
	
	@Override
	public void init(ServletConfig config) throws ServletException {
		// TODO Auto-generated method stub
	    String versao = config.getServletContext().getInitParameter("versao");

	    config.getServletContext().setAttribute("versao", versao);
	    
		super.init(config);
	}
	
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		ServletContext context = getServletContext();
	    String versao = context.getInitParameter("versao");

		request.setAttribute("versao", versao);
		sendRedirect(request, response);
	}
	
	
	
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setCharacterEncoding("UTF-8");
		response.setContentType("text/html; charset=UTF-8");
		
		List<String> errors = new ArrayList<String>();
		try {
			if(request.getUserPrincipal() == null) {
				String username = request.getParameter("username");
				String password = request.getParameter("password");
				
				if (ValidacaoHelper.isEmpty(username)) {
					errors.add("Usuário é obrigatório");
				}
				
				if (ValidacaoHelper.isEmpty(password)) {
					errors.add("Senha é obrigatório");
				}
				
				if(ValidacaoHelper.isNotEmpty(errors)) {
					throw new Exception("Campos obrigatórios não preenchidos");
				}
				
				request.login(username, password);
			}
			
			sendRedirect(request, response);
		} catch (Exception e) {
			String errorMessage = (String) request.getAttribute("errorMessage");
			if(ValidacaoHelper.isNotEmpty(errorMessage)) {
				errors.add(errorMessage);
			}
			
			request.setAttribute("errors", errors);
			RequestDispatcher dispatcher = request.getRequestDispatcher("/login.jsp");
			dispatcher.forward(request, response);
		}
	}
	
	private void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
		String pageToSend = request.getContextPath();
		try {
			
			if(request.getUserPrincipal() != null) {
				LoginTypeEnum loginType = (LoginTypeEnum) request.getAttribute("loginType");
				
				if(loginType == null) {
					pageToSend = LOGGED_INDEX_PAGE;
				} else {
					switch (loginType) {
						case USER:
							pageToSend = LOGGED_INDEX_PAGE;
							break;
						case MANIFESTATION: {
							TbManifestacao manifestation = (TbManifestacao) request.getAttribute("manifestation");
							pageToSend = String.format(
									MANIFESTATION_DETAIL_PAGE,
									manifestation.getNrManifestacao(),
									manifestation.getIdManifestacao());
							break;
						}
						case NEW_PASSWORD:
							pageToSend = "/novasenha.xhtml";
							break;
					}
				}
			} else {
				pageToSend = "/login.jsp";
			}
			
			RequestDispatcher dispatcher = request.getRequestDispatcher(pageToSend);
			dispatcher.forward(request, response);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
}