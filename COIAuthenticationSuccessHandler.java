package sg.edu.nus.coi.security;

import java.io.IOException;
import java.time.LocalDate;
import java.time.Year;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.NotFoundException;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.CollectionUtils;

import sg.edu.nus.coi.domain.AnnualCOISetup;
import sg.edu.nus.coi.domain.StaffParticular;
import sg.edu.nus.coi.domain.UserRoleType;
import sg.edu.nus.coi.enums.ProxyDeclarantTypeEnum;
import sg.edu.nus.coi.service.AuthorizationService;
import sg.edu.nus.coi.service.ConfigurationService;
import sg.edu.nus.coi.service.DeclarationService;
import sg.edu.nus.coi.service.ProcessMakerWebService;
import sg.edu.nus.coi.service.common.EmailService;
import sg.edu.nus.coi.util.CoiUtil;
import sg.edu.nus.coi.util.Constants;
import sg.edu.nus.coi.util.StringUtil;
import sg.edu.nus.coi.ws.response.StaffData;
import sg.edu.nus.coi.ws.response.StaffResponse;

public class COIAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private static final Logger logger = Logger.getLogger(COIAuthenticationSuccessHandler.class);

	@Autowired
	private AuthorizationService authorizationService;
	@Autowired
	private ProcessMakerWebService processMakerWebService;
	@Autowired
	private DeclarationService declarationService;
	@Autowired
	private EmailService emailService;
	@Autowired
	private ConfigurationService configurationService;

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		String userName = "";

		Object principal = authentication.getPrincipal();

		if (principal instanceof UserDetails) {
			userName = ((UserDetails) principal).getUsername().toUpperCase();
		} else {
			userName = principal.toString().toUpperCase();
		}

		AnnualCOISetup annualCOISetup = configurationService.getAnnualCOISetup(String.valueOf(Year.now().getValue()));

		populateStaffParticular(request, userName, CoiUtil.isInAnnualDeclarationPeriod(annualCOISetup));

		if (null == request.getSession().getAttribute("staffParticular")) {
			logger.error("Staff particular does not exist in both COI and HR database.");
			throw new RuntimeException("Staff particular does not exist in both COI and HR database.");
		}

		Set<String> roles = authentication.getAuthorities().stream()
				.map(r -> r.getAuthority().substring(r.getAuthority().lastIndexOf("_") + 1))
				.collect(Collectors.toSet());

		request.getSession().setAttribute("menuList", authorizationService.getMenuforRole(roles));

		if (null != request.getSession().getAttribute("isRootEntered")) {
			request.getSession().removeAttribute("isRootEntered");
		}

		String targetUrl = getLandingUrl(request, roles);
		redirectStrategy.sendRedirect(request, response, targetUrl);
	}

	private String getLandingUrl(HttpServletRequest request, Set<String> roles) {

		if (isAdvisor(roles)) {
			return "/reviewer";
		}

		/*if (isNormalUserOnly(roles)) {
			if (isEligibleForAnnualDeclaration(request)) {
				return "/declarationForm";
			} else {
				return "/viewEditDeclarations";
			}
		}*/

		return "/home";
	}

	private void populateStaffParticular(HttpServletRequest request, String userId, boolean isAnnualDeclarationPeriod) {
		
		if (!StringUtil.isNotEmptyOrNull(userId)) {
			logger.error("Exception when populating staff paticular. Invalid NUSNetId.");
			throw new IllegalArgumentException("Exception when populating staff paticular. Invalid NUSNetId.");
		}

		try {

			StaffParticular coiStfHistRecord = declarationService.getStaffPaticular(userId,
					String.valueOf(Year.now().getValue()));

			if (isBatchUploadStaffRecord(coiStfHistRecord) && isAnnualDeclarationPeriod) {
				logger.debug("Staff Particulars found in application DB. User ID: " + userId);
				request.getSession().setAttribute("staffParticular", coiStfHistRecord);
				return;
			}

			StaffResponse staffResponse = processMakerWebService.getStaffInfo("CCEHC");

			if (null != staffResponse && Constants.WebServiceReponseCode.SUCCESS.equals(staffResponse.getCode())) {

				StaffData data = staffResponse.getStaffData();

				if (null != data && StringUtil.isNotEmptyOrNull(data.getEmployeeId())) {

					logger.debug("Staff ID returned by ESB WS: " + data.getEmployeeId());

					StaffParticular staffParticular = declarationService.getStaffPaticular(data.getUserId(),
							data.getEmployeeId(), String.valueOf(Year.now().getValue()));

					if (isBatchUploadStaffRecord(staffParticular) && isAnnualDeclarationPeriod) {
						request.getSession().setAttribute("staffParticular", staffParticular);
						return;
					}
					
					StaffParticular staffParticularFromChrs = declarationService.getStaffParticularsFromCHRSView(data.getEmployeeId());
					

				/*	StaffPaticularResponse staffPaticularResponse = processMakerWebService
							.getStaffPaticular(data.getEmployeeId());

					if (null != staffPaticularResponse
							&& Constants.WebServiceReponseCode.SUCCESS.equals(staffPaticularResponse.getCode())) {*/
					
					if(null != staffParticularFromChrs) {

						//StaffParticularData staffParticularData = staffPaticularResponse.getStaffPaticularData();

						if (StringUtil.isNotEmptyOrNull(staffParticularFromChrs.getStaffUserId())) {

							//StaffParticular esbStaff = CoiUtil.copyStaffParticsFromESB(staffParticularData);
							staffParticularFromChrs.setRecUpdateUserId(CoiUtil.getNusnetId());

							if (null == staffParticular
									|| (null != staffParticular && !staffParticular.equals(staffParticularFromChrs))) {
								// hardcoded for testing
								//Code faculty = new Code("0350", "YaleNUS Faculty");
								//esbStaff.setFaculty(faculty);
								logger.debug("coiStfHistRecord != staffParticularFromChrs");
								request.getSession().setAttribute("staffParticular", staffParticularFromChrs);
							} else {
								// hardcoded for testing
								//Code faculty = new Code("0350", "YaleNUS Faculty");
								//staffParticular.setFaculty(faculty);
								
								logger.debug("coiStfHistRecord == staffParticularFromChrs");
								request.getSession().setAttribute("staffParticular", staffParticular);
							}
							
							

						} else {
							logger.error("Error when populating staff paticular from HR. NUSNetId is empty or null.");
						}

					} else {
						logger.error("Error when retrieve staff paticular from HR. UserId: " + userId);
						throw new NotFoundException();
					}
				}
			} else {
				logger.error("Error when retrieve staff paticular from VUA. UserId: " + userId);
				throw new NotFoundException();
			}

		} catch (Exception e) {
			logger.error("Exception when populating staff paticular. " + e);
			emailService.sendErrorNotification(null,
					"Exception when populating staff paticular. User Id: " + userId + ". " + e);
		}

	}

	private boolean isEligibleForAnnualDeclaration(HttpServletRequest request) {
		StaffParticular staffParticular = (StaffParticular) request.getSession().getAttribute("staffParticular");

		AnnualCOISetup annualCOISetup = configurationService
				.getAnnualCOISetup(String.valueOf(LocalDate.now().getYear()));

		if (CoiUtil.isInAnnualDeclarationPeriod(annualCOISetup)) {
			List<String> existAnnualDeclNos = declarationService.getAnnualDeclarationNos(
					staffParticular.getSapStaffNo(), String.valueOf(LocalDate.now().getYear()), "");

			List<String> existAnnualProxyDeclNos = declarationService.getAnnualProxyDeclarationNos(
					staffParticular.getSapStaffNo(), ProxyDeclarantTypeEnum.STAFF_NUMBER.getCode(),
					String.valueOf(LocalDate.now().getYear()), "");

			if ((CollectionUtils.isEmpty(existAnnualDeclNos) && CollectionUtils.isEmpty(existAnnualProxyDeclNos))) {
				return true;
			}
		}

		return false;
	}

	private boolean isNormalUserOnly(Set<String> roles) {
		return !CollectionUtils.isEmpty(roles) && roles.size() == 1
				&& roles.contains(authorizationService.getDetaultRoleType().getAccesstp_c());
	}

	private boolean isAdvisor(Set<String> roles) {
		List<UserRoleType> roleTypes = authorizationService.getUserRoleTypes(new ArrayList<>(roles));
		return !CollectionUtils.isEmpty(roleTypes) && roleTypes.stream()
				.anyMatch(roleType -> Constants.RoleAcess.ADVISOR.equals(roleType.getAccess_cat_c()));
	}

	private boolean isBatchUploadStaffRecord(StaffParticular coiStfHistRecord) {
		return null != coiStfHistRecord
				&& Constants.StaffRecordUploadType.BATCH.equals(coiStfHistRecord.getUploadType());
	}
}
