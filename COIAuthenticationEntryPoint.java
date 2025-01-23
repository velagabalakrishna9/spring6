package sg.edu.nus.coi.security;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;


import nus.cc.wsone.WorkspaceOneAuthenticator;
import sg.edu.nus.coi.resource.ApplicationProperties;
import sg.edu.nus.coi.util.CoiCrypter;
import sg.edu.nus.coi.util.CoiUtil;
import sg.edu.nus.coi.util.Constants;

public class COIAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private static final Logger logger = Logger.getLogger(COIAuthenticationEntryPoint.class);

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
			throws IOException, ServletException {
		
		try {
			HttpSession session = request.getSession(true);
			String appId = ApplicationProperties.get().getSysParamValue(Constants.ApplicationProperties.WSONE_ID);
			String redirectUrl = ApplicationProperties.get().getSysParamValue(Constants.ApplicationProperties.WSONE_REDIRECT);
			String scretkey = ApplicationProperties.get().getSysParamValue(Constants.ApplicationProperties.WSONE_SECRETKEY);
			String decrptedStr =  CoiCrypter.decrypt(CoiUtil.getEncryptionKey(), CoiUtil.getEncryptionSalt(), scretkey);
			
			WorkspaceOneAuthenticator wsOneOAuth = new WorkspaceOneAuthenticator(appId, decrptedStr,redirectUrl);
			response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY);
			response.sendRedirect(wsOneOAuth.getAuthorized(session));

		} catch (Exception wsone) {
			logger.error("WS1Exeption encountered.", wsone);

		}

	}

}
