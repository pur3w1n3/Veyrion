package com.aq.jvmsentinel.worker;

import com.aq.jvmsentinel.model.SqlEvent;
import com.aq.jvmsentinel.model.VerificationStatus;

import java.util.Locale;
import java.util.Objects;

/**
 * D2 differential helper: benign vs metachar SQL structure comparison.
 * Structural influence → DYNAMIC_SUSPECTED at most (never VERIFIED).
 */
public final class SqlDiffProbe {
    public static final String META_MARKER = "'\"veyrion-sqli-meta";

    private SqlDiffProbe() { }

    public record DiffResult(boolean structureInfluenced, VerificationStatus status, String summary) { }

    public static DiffResult compare(SqlEvent benign, SqlEvent meta) {
        Objects.requireNonNull(benign, "benign");
        Objects.requireNonNull(meta, "meta");
        String left = normalize(benign.sqlText());
        String right = normalize(meta.sqlText());
        if (left.equals(right)) {
            return new DiffResult(false, VerificationStatus.DYNAMIC_SUSPECTED,
                    "SQL text unchanged under metachar probe");
        }
        boolean metaInSql = right.contains(META_MARKER.toLowerCase(Locale.ROOT))
                || meta.maliciousFragmentPresent();
        boolean quoteCountChanged = count(left, '\'') != count(right, '\'')
                || count(left, '"') != count(right, '"');
        boolean influenced = metaInSql || quoteCountChanged || !tokenShape(left).equals(tokenShape(right));
        if (!influenced) {
            return new DiffResult(false, VerificationStatus.DYNAMIC_SUSPECTED,
                    "SQL differed without clear structural influence");
        }
        return new DiffResult(true, VerificationStatus.DYNAMIC_SUSPECTED,
                "D2: metachar probe influenced SQL structure (MOCK); not VERIFIED");
    }

    private static String normalize(String sql) {
        return sql == null ? "" : sql.replaceAll("\\s+", " ").trim().toLowerCase(Locale.ROOT);
    }

    private static String tokenShape(String sql) {
        return sql.replaceAll("'[^']*'", "'?'")
                .replaceAll("\"[^\"]*\"", "\"?\"")
                .replaceAll("\\d+", "?");
    }

    private static int count(String value, char c) {
        int n = 0;
        for (int i = 0; i < value.length(); i++) if (value.charAt(i) == c) n++;
        return n;
    }
}
