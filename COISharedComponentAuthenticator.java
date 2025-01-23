package sg.edu.nus.coi.security;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import sg.edu.nus.coi.domain.UserRoleAccess;
import sg.edu.nus.coi.domain.UserRoleType;
import sg.edu.nus.coi.service.AuthorizationService;

public class COISharedComponentAuthenticator implements AuthenticationProvider {

	private static final String ROLE_PREFIC = "ROLE_";
	private static final Logger logger = LogManager.getLogger(COISharedComponentAuthenticator.class);

	@Autowired
	private AuthorizationService authorizationService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		try {
			logger.info("COISharedComponentAuthenticator - authenticate - Begin");
			UserRoleAccess userData = new UserRoleAccess();
			userData.setUser_i(authentication.getName());
			List<UserRoleAccess> roleList = authorizationService.getRoleforUser(userData.getUser_i());
			Collection<? extends GrantedAuthority> grantedAuthorities = this.getGrantedAuthorities(roleList);
			UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken(
					new User(authentication.getName().toUpperCase(), "", grantedAuthorities),
					(String) authentication.getCredentials(), grantedAuthorities);

			return user;
		} catch (Exception e) {
			throw new BadCredentialsException(authentication.getName());
		}
	}

	@Override
	public boolean supports(Class authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}

	private Collection<? extends GrantedAuthority> getGrantedAuthorities(List<UserRoleAccess> roleList) {

		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();

		if (roleList != null && !roleList.isEmpty()) {
			for (UserRoleAccess roleAccess : roleList) {
				authorities.add(new SimpleGrantedAuthority(ROLE_PREFIC + roleAccess.getAccesstp_c()));
				logger.info("User Role :" + roleAccess.getAccesstp_c());
			}
		} else {
			UserRoleType defaultRoleType = authorizationService.getDetaultRoleType();
			if (null != defaultRoleType) {
				authorities.add(new SimpleGrantedAuthority(ROLE_PREFIC + defaultRoleType.getAccesstp_c()));
			}
		}

		return authorities;
	}

}
