package sg.edu.nus.coi.security;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.CollectionUtils;

import nus.cc.wsone.WorkspaceOneAuthenticator;
import sg.edu.nus.coi.domain.UserRoleAccess;
import sg.edu.nus.coi.domain.UserRoleType;
import sg.edu.nus.coi.domain.common.SysParam;
import sg.edu.nus.coi.enums.EnvironmentEnum;
import sg.edu.nus.coi.resource.ApplicationProperties;
import sg.edu.nus.coi.service.AuthorizationService;
import sg.edu.nus.coi.service.common.SysParamService;
import sg.edu.nus.coi.util.CoiCrypter;
import sg.edu.nus.coi.util.CoiUtil;
import sg.edu.nus.coi.util.Constants;

public class COIAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private static final Logger logger = Logger.getLogger(COIAuthenticationProcessingFilter.class);
	public COIAuthenticationProcessingFilter() {
		super("/postLogin");
	}

	@Autowired
	private AuthorizationService authorizationService;

	@Autowired
	private MessageSource messageSource;
	
	@Autowired
	private SysParamService sysParamService;

	private static final String ROLE_PREFIC = "ROLE_";

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		String url = ((HttpServletRequest) req).getServletPath();
		MDC.put("user", getLoginUserId());
		if (Constants.ROOT_URL.equals(url)) {
			((HttpServletRequest) req).getSession().setAttribute("isRootEntered", Constants.YES);
			SecurityContextHolder.getContext().setAuthentication(null);
		}
		super.doFilter(req, res, chain);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		logger.info("Attempt Authentication - Begin");

		if (authentication != null) {
			authentication = getAuthenticationManager().authenticate(authentication);
		} else {
			
			try {
				
				String appId = ApplicationProperties.get().getSysParamValue(Constants.ApplicationProperties.WSONE_ID);
				String redirectUrl = ApplicationProperties.get().getSysParamValue(Constants.ApplicationProperties.WSONE_REDIRECT);
				String scretkey = ApplicationProperties.get().getSysParamValue(Constants.ApplicationProperties.WSONE_SECRETKEY);
				String decrptedStr =  CoiCrypter.decrypt(CoiUtil.getEncryptionKey(), CoiUtil.getEncryptionSalt(), scretkey);
				
				WorkspaceOneAuthenticator wsOneOAuth = new WorkspaceOneAuthenticator(appId,decrptedStr,redirectUrl);
				
				HttpSession session = request.getSession(true);
				String code = request.getParameter("code");
				String state = request.getParameter("state");
			
			
			    if (StringUtils.isNotBlank(code)
					   && wsOneOAuth.isAuthenticated(code,state,session) && isValidDomain(wsOneOAuth)) {

				   logger.info("WSOne Authentication sucess for user " + wsOneOAuth.getUserid() + " via "
						+ request.getRemoteAddr());

				String userName = "CCEHC"; 
						//wsOneOAuth.getUserid().toUpperCase();
				
				UserRoleAccess userData = new UserRoleAccess();
				userData.setUser_i(userName);
				List<UserRoleAccess> roleList = authorizationService.getRoleforUser(userData.getUser_i());

				Collection<? extends GrantedAuthority> authorities = getAuthorities(roleList);

				if (CollectionUtils.isEmpty(authorities)) {
					authentication = null;
					throw new LockedException(messageSource.getMessage("error.login.temporarily.locked", null, null));
				} else {
					UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(
							new User(userName.toUpperCase(), "", authorities), userName.toUpperCase(), authorities);
					authentication = user;
				}

			} else {
				logger.info("WSOne Authentication failed for user " + wsOneOAuth.getUserid() + " via "
						+ request.getRemoteAddr());
				authentication = null;
				throw new BadCredentialsException(messageSource.getMessage("error.login.invalid", null, null));
			}
		  } catch (Exception wsone) {
				logger.error("WS1Exeption encountered.", wsone);

			}
		}

		return authentication;
	}

	private Collection<? extends GrantedAuthority> getAuthorities(List<UserRoleAccess> roleList) {

		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();

		if (roleList != null && !roleList.isEmpty()) {
			for (UserRoleAccess roleAccess : roleList) {
				authorities.add(new SimpleGrantedAuthority(ROLE_PREFIC + roleAccess.getAccesstp_c()));
				logger.info("User Role :" + roleAccess.getAccesstp_c());
			}
		} else {
			SysParam start = sysParamService.getSysParam(CoiUtil.getParamWEnv(Constants.ApplicationProperties.MAINTENANCE_PERIOD_START_DATE));
			SysParam end = sysParamService.getSysParam(CoiUtil.getParamWEnv(Constants.ApplicationProperties.MAINTENANCE_PERIOD_END_DATE));
			if (!CoiUtil.isInMaintenancePeriod(start, end)) {
				UserRoleType defaultRoleType = authorizationService.getDetaultRoleType();
				if (null != defaultRoleType) {
					authorities.add(new SimpleGrantedAuthority(ROLE_PREFIC + defaultRoleType.getAccesstp_c()));
				}
			}
		}

		return authorities;
	}

	private boolean isValidDomain(WorkspaceOneAuthenticator wsoneAuth) {
		EnvironmentEnum currEnv = CoiUtil.getCurrentEnvironment();
		if (EnvironmentEnum.PRODUCTION.equals(currEnv) || EnvironmentEnum.QAT.equals(currEnv)) {
			if (wsoneAuth.getUsertype().equals(Constants.Domain.NUSSTF)) {
				return true;
			}
		} else {
			if (wsoneAuth.getUsertype().equals(Constants.Domain.NUSSTF)
					|| wsoneAuth.getUsertype().equals(Constants.Domain.NUSEXT)) {
				return true;
			}
		}
		return false;
	}
	
	private String getLoginUserId() {
		String userId = "SYSTEM";
		try {				
			userId = CoiUtil.getNusnetId();					
		} catch (Exception e) {
			// e.printStackTrace();
		}
		return userId;
	}
}
