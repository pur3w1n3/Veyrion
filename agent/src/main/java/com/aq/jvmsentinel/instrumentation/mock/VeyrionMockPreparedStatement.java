package com.aq.jvmsentinel.instrumentation.mock;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLXML;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Calendar;

final class VeyrionMockPreparedStatement extends VeyrionMockStatement implements PreparedStatement {
    private final String sql;

    VeyrionMockPreparedStatement(VeyrionMockConnection connection, String sql) {
        super(connection);
        this.sql = sql == null ? "" : sql;
    }

    @Override
    public ResultSet executeQuery() {
        return executeQuery(sql);
    }

    @Override
    public int executeUpdate() {
        return executeUpdate(sql);
    }

    @Override
    public boolean execute() {
        return execute(sql);
    }

    @Override
    public void setNull(int parameterIndex, int sqlType) {
    }

    @Override
    public void setBoolean(int parameterIndex, boolean x) {
    }

    @Override
    public void setByte(int parameterIndex, byte x) {
    }

    @Override
    public void setShort(int parameterIndex, short x) {
    }

    @Override
    public void setInt(int parameterIndex, int x) {
    }

    @Override
    public void setLong(int parameterIndex, long x) {
    }

    @Override
    public void setFloat(int parameterIndex, float x) {
    }

    @Override
    public void setDouble(int parameterIndex, double x) {
    }

    @Override
    public void setBigDecimal(int parameterIndex, BigDecimal x) {
    }

    @Override
    public void setString(int parameterIndex, String x) {
    }

    @Override
    public void setBytes(int parameterIndex, byte[] x) {
    }

    @Override
    public void setDate(int parameterIndex, Date x) {
    }

    @Override
    public void setTime(int parameterIndex, Time x) {
    }

    @Override
    public void setTimestamp(int parameterIndex, Timestamp x) {
    }

    @Override
    public void setAsciiStream(int parameterIndex, InputStream x, int length) {
    }

    @Deprecated
    @Override
    public void setUnicodeStream(int parameterIndex, InputStream x, int length) {
    }

    @Override
    public void setBinaryStream(int parameterIndex, InputStream x, int length) {
    }

    @Override
    public void clearParameters() {
    }

    @Override
    public void setObject(int parameterIndex, Object x, int targetSqlType) {
    }

    @Override
    public void setObject(int parameterIndex, Object x) {
    }

    @Override
    public void addBatch() {
        addBatch(sql);
    }

    @Override
    public void setCharacterStream(int parameterIndex, Reader reader, int length) {
    }

    @Override
    public void setRef(int parameterIndex, Ref x) {
    }

    @Override
    public void setBlob(int parameterIndex, Blob x) {
    }

    @Override
    public void setClob(int parameterIndex, Clob x) {
    }

    @Override
    public void setArray(int parameterIndex, Array x) {
    }

    @Override
    public ResultSetMetaData getMetaData() {
        return VeyrionMockResultSet.empty().getMetaData();
    }

    @Override
    public void setDate(int parameterIndex, Date x, Calendar cal) {
    }

    @Override
    public void setTime(int parameterIndex, Time x, Calendar cal) {
    }

    @Override
    public void setTimestamp(int parameterIndex, Timestamp x, Calendar cal) {
    }

    @Override
    public void setNull(int parameterIndex, int sqlType, String typeName) {
    }

    @Override
    public void setURL(int parameterIndex, URL x) {
    }

    @Override
    public ParameterMetaData getParameterMetaData() throws SQLException {
        throw new SQLException("parameter metadata is not mocked");
    }

    @Override
    public void setRowId(int parameterIndex, RowId x) {
    }

    @Override
    public void setNString(int parameterIndex, String value) {
    }

    @Override
    public void setNCharacterStream(int parameterIndex, Reader value, long length) {
    }

    @Override
    public void setNClob(int parameterIndex, NClob value) {
    }

    @Override
    public void setClob(int parameterIndex, Reader reader, long length) {
    }

    @Override
    public void setBlob(int parameterIndex, InputStream inputStream, long length) {
    }

    @Override
    public void setNClob(int parameterIndex, Reader reader, long length) {
    }

    @Override
    public void setSQLXML(int parameterIndex, SQLXML xmlObject) {
    }

    @Override
    public void setObject(int parameterIndex, Object x, int targetSqlType, int scaleOrLength) {
    }

    @Override
    public void setAsciiStream(int parameterIndex, InputStream x, long length) {
    }

    @Override
    public void setBinaryStream(int parameterIndex, InputStream x, long length) {
    }

    @Override
    public void setCharacterStream(int parameterIndex, Reader reader, long length) {
    }

    @Override
    public void setAsciiStream(int parameterIndex, InputStream x) {
    }

    @Override
    public void setBinaryStream(int parameterIndex, InputStream x) {
    }

    @Override
    public void setCharacterStream(int parameterIndex, Reader reader) {
    }

    @Override
    public void setNCharacterStream(int parameterIndex, Reader value) {
    }

    @Override
    public void setClob(int parameterIndex, Reader reader) {
    }

    @Override
    public void setBlob(int parameterIndex, InputStream inputStream) {
    }

    @Override
    public void setNClob(int parameterIndex, Reader reader) {
    }
}
