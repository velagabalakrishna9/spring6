package sg.edu.nus.coi.resource;

import java.util.Properties;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.apache.log4j.Logger;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

public abstract class ApplicationPropertiesInitializer implements ServletContextListener {
	private static final Logger logger = Logger.getLogger(ApplicationPropertiesInitializer.class);
	
	@Override
	public void contextInitialized(ServletContextEvent sce) {
		ApplicationContext ctx = WebApplicationContextUtils.getWebApplicationContext(sce.getServletContext());
        ctx.getAutowireCapableBeanFactory().autowireBean(this);
		//final ServletContext ctx = sce.getServletContext();
		//ctx.log("*************************************************************");
		//ctx.log("**                    app startup                          **");
		//ctx.log("*************************************************************");
        logger.info("loadProperties - Begin");
        
		ApplicationProperties.get().putAll(loadProperties());
	}

	/**
	 * Loads properties from the desired data source (e.g. database, LDAP,...)
	 * 
	 * @return initialised properties instance
	 */
	protected abstract Properties loadProperties();

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
		final ServletContext ctx = sce.getServletContext();
		ctx.log("*************************************************************");
		ctx.log("**                    app shutdown                         **");
		ctx.log("*************************************************************");
	}

}