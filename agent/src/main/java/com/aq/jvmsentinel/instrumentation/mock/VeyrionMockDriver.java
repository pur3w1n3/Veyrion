package com.aq.jvmsentinel.instrumentation.mock;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Properties;
import java.util.logging.Logger;

/** In-sandbox JDBC driver for deny-all Docker runs. Never opens a real network socket. */
public final class VeyrionMockDriver implements Driver {
    public static final String URL_PREFIX = "jdbc:veyrion-mock:";

    static {
        try {
            DriverManager.registerDriver(new VeyrionMockDriver());
        } catch (SQLException ignored) {
            // registration is best-effort at class init; agent premain also registers
        }
    }

    public static void register() {
        try {
            DriverManager.registerDriver(new VeyrionMockDriver());
        } catch (SQLException ignored) {
        }
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) return null;
        return new VeyrionMockConnection(url == null ? URL_PREFIX + "mem" : url);
    }

    @Override
    public boolean acceptsURL(String url) {
        return url != null && url.startsWith(URL_PREFIX);
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
        return new DriverPropertyInfo[0];
    }

    @Override
    public int getMajorVersion() {
        return 1;
    }

    @Override
    public int getMinorVersion() {
        return 0;
    }

    @Override
    public boolean jdbcCompliant() {
        return false;
    }

    @Override
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {
        throw new SQLFeatureNotSupportedException("veyrion mock driver has no parent logger");
    }
}
