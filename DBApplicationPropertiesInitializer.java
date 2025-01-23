package sg.edu.nus.coi.resource;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

//import javax.naming.Context;
//import javax.naming.InitialContext;
import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


/**
 * Loads application configuration from the database
 */
@Component
public class DBApplicationPropertiesInitializer extends ApplicationPropertiesInitializer {

	private static Log logger = LogFactory.getLog(DBApplicationPropertiesInitializer.class.getName());
	private static final String QUERY = "select param_n, param_val_t from cois_control_param";
	
	
	private DataSource ds;
	
	@Autowired
	public void setDataSource(DataSource dataSource) {
		this.ds = dataSource;
	}
	
	@Override
	protected Properties loadProperties() {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		final Properties props = new Properties();
		try {

			conn = ds.getConnection();
			
			ps = conn.prepareStatement(QUERY);
			rs = ps.executeQuery();

			while (rs.next()) {
				props.setProperty(rs.getString("param_n").trim(),
						(null != rs.getString("param_val_t")) ? rs.getString("param_val_t").trim() : "");
			}
			rs.close();
			ps.close();
			conn.close();
		} catch (Exception e) {
			logger.error("Exception in populating application configuration from database.", e);
		} finally {
			try {
				if (null != rs) {
					rs.close();
				}
			} catch (SQLException e) {
				logger.error("Exception in populating application configuration from database - closing ResultSet.", e);
			}
			try {
				if (null != ps) {
					ps.close();
				}
			} catch (SQLException e) {
				logger.error(
						"Exception in populating application configuration from database - closing PreparedStatement.",
						e);
			}
			try {
				if (null != conn) {
					conn.close();
				}
			} catch (SQLException e) {
				logger.error("Exception in populating application configuration from database - closing Connection.",
						e);
			}
		}

		return props;
	}


}