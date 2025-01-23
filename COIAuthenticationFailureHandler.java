package sg.edu.nus.coi.security;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

public class COIAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	private static final Logger logger = Logger.getLogger(COIAuthenticationFailureHandler.class);

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		
		logger.info("Login failed. " + exception.getMessage());
		
		request.getSession().removeAttribute("menuList");
		
		if(exception.getClass().isAssignableFrom(LockedException.class)) {
            setDefaultFailureUrl("/maintenance.html");
		} else {
			setDefaultFailureUrl("/loginfailed.html");
		}
		
		super.onAuthenticationFailure(request, response, exception);
	}

}
