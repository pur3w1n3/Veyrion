package org.springframework.jdbc.datasource;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Test stub mirroring Spring's URL-configurable DataSource surface so agent
 * call-site / definition-site JDBC-SSRF instrumentation can be exercised
 * without pulling spring-jdbc onto the agent classpath.
 */
public class DriverManagerDataSource {
    private String url;
    private String username;
    private String password;

    public void setUrl(String url) {
        this.url = url;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUrl() {
        return url;
    }

    public Connection getConnection() throws SQLException {
        if (url == null || url.isBlank()) {
            throw new SQLException("url required");
        }
        // No real network — fixture only needs the method boundary for agent advice.
        return null;
    }
}
