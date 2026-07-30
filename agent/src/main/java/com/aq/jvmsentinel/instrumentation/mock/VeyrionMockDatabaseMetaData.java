package com.aq.jvmsentinel.instrumentation.mock;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;

/** 基于代理的 DatabaseMetaData，避免跨 runtime 的 JDK 表面对不齐。 */
final class VeyrionMockDatabaseMetaData {
    private VeyrionMockDatabaseMetaData() {
    }

    static DatabaseMetaData create(String url, Connection connection) {
        return (DatabaseMetaData) Proxy.newProxyInstance(
                DatabaseMetaData.class.getClassLoader(),
                new Class<?>[]{DatabaseMetaData.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    Class<?> returnType = method.getReturnType();
                    if ("getURL".equals(name)) {
                        return url;
                    }
                    if ("getConnection".equals(name)) {
                        return connection;
                    }
                    if ("getDatabaseProductName".equals(name)) {
                        return "VeyrionMock";
                    }
                    if ("getDatabaseProductVersion".equals(name)
                            || "getDriverName".equals(name)
                            || "getDriverVersion".equals(name)) {
                        return "veyrion-mock-0.1";
                    }
                    if ("getUserName".equals(name)) {
                        return "veyrion";
                    }
                    if ("getCatalog".equals(name) || "getSchema".equals(name)
                            || "getCatalogSeparator".equals(name)
                            || "getCatalogTerm".equals(name)
                            || "getSchemaTerm".equals(name)
                            || "getProcedureTerm".equals(name)
                            || "getSearchStringEscape".equals(name)
                            || "getIdentifierQuoteString".equals(name)
                            || "getSQLKeywords".equals(name)
                            || "getNumericFunctions".equals(name)
                            || "getStringFunctions".equals(name)
                            || "getSystemFunctions".equals(name)
                            || "getTimeDateFunctions".equals(name)
                            || "getExtraNameCharacters".equals(name)) {
                        return "";
                    }
                    if (ResultSet.class.isAssignableFrom(returnType)) {
                        return VeyrionMockResultSet.empty();
                    }
                    if (returnType == boolean.class) {
                        return Boolean.FALSE;
                    }
                    if (returnType == int.class) {
                        return 0;
                    }
                    if (returnType == long.class) {
                        return 0L;
                    }
                    if (returnType == String.class) {
                        return "";
                    }
                    if ("unwrap".equals(name)) {
                        Class<?> iface = (Class<?>) args[0];
                        if (iface.isInstance(proxy)) {
                            return proxy;
                        }
                        throw new SQLException("not a wrapper for " + iface.getName());
                    }
                    if ("isWrapperFor".equals(name)) {
                        return ((Class<?>) args[0]).isInstance(proxy);
                    }
                    if (returnType == void.class) {
                        return null;
                    }
                    return null;
                });
    }
}
