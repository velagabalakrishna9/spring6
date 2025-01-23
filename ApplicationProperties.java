package sg.edu.nus.coi.resource;

import java.util.Properties;

import sg.edu.nus.coi.util.CoiUtil;

public final class ApplicationProperties extends Properties {

	private static final long serialVersionUID = 1L;
	private static ApplicationProperties instance;

	private ApplicationProperties() {
	}

	public String getSysParamValue(String param) {
		String paramVal = "";
		String paramName = new StringBuilder(param).append(".")
				.append(CoiUtil.getCurrentEnvironment().getEnvironmentCode()).toString();
		paramVal = this.getProperty(paramName);
		return paramVal;
	}

	public static final ApplicationProperties get() {
		if (instance == null)
			instance = new ApplicationProperties();

		return instance;
	}

}
