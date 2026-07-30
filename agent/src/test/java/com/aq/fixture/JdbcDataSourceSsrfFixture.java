package com.aq.fixture;

import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 * Mirrors kvf {@code CommonController#testDatabaseConnection}:
 * Class.forName → DriverManagerDataSource#setUrl → #getConnection.
 */
public final class JdbcDataSourceSsrfFixture {
    private JdbcDataSourceSsrfFixture() {
    }

    public static void main(String[] args) throws Exception {
        Class.forName("com.aq.fixture.JdbcDataSourceSsrfFixture");
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setUrl("jdbc:mysql://127.0.0.1:3306/veyrion");
        dataSource.setUsername("veyrion");
        dataSource.setPassword("veyrion");
        try {
            dataSource.getConnection();
        } catch (Exception ignored) {
            // stub may return null; boundary still observed
        }
        System.out.println("JdbcDataSourceSsrfFixture: PASS");
    }
}
