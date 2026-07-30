package com.aq.fixture;

import com.zaxxer.hikari.HikariConfig;

/** Mirrors Hikari setJdbcUrl SSRF surface outside application classPrefix. */
public final class HikariJdbcUrlFixture {
    private HikariJdbcUrlFixture() {
    }

    public static void main(String[] args) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://127.0.0.1:3306/veyrion");
        System.out.println("HikariJdbcUrlFixture: PASS");
    }
}
