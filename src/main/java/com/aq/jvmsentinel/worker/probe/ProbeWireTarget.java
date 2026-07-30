package com.aq.jvmsentinel.worker.probe;

import java.util.Locale;
import java.util.Set;

/**
 * 复现 {@code LoopbackHttpProbe} 的 wire {@code requestTarget} 规则，供覆盖校验对齐计划与事件。
 *
 * <p>form/multipart POST 把 query 放进 body，事件里 {@code requestTarget} 仅为 route；
 * 读侧 GET 可能追加穿越 path 参数。校验器若仍用朴素 {@code route?query} 会假阴性。</p>
 */
public final class ProbeWireTarget {
    private ProbeWireTarget() { }

    /**
     * 与 agent {@code LoopbackHttpProbe#probeOne} 写入事件的 {@code requestTarget} 一致。
     */
    public static String requestTarget(String method, String route, String query) {
        String httpMethod = method == null ? "" : method.toUpperCase(Locale.ROOT);
        String path = route == null ? "" : route;
        String q = query == null ? "" : query;
        boolean fileRead = looksFileReadDownload(path, q);
        boolean multipart = !fileRead && Set.of("POST", "PUT", "PATCH").contains(httpMethod)
                && looksMultipartUpload(path, q);
        boolean form = !multipart && Set.of("POST", "PUT", "PATCH").contains(httpMethod)
                && (fileRead || looksFormUrlEncoded(path, q));
        if (multipart || form || q.isEmpty()) {
            return path;
        }
        return path + "?" + ensureTraversalReadQuery(q, fileRead);
    }

    /** 与 agent 同名启发式保持同步；漂移时以 LoopbackHttpProbe 为准。 */
    static boolean looksMultipartUpload(String route, String query) {
        if (looksFileReadDownload(route, query)) {
            return false;
        }
        String r = route == null ? "" : route.toLowerCase(Locale.ROOT);
        if (r.contains("upload") || r.contains("multipart") || r.contains("fileupload")) {
            return true;
        }
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (q.isBlank()) {
            return false;
        }
        for (String pair : q.split("&", -1)) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
            if ("file".equals(name) || "multipartfile".equals(name)
                    || name.endsWith("file") && name.contains("upload")) {
                return true;
            }
        }
        return false;
    }

    static boolean looksFileReadDownload(String route, String query) {
        String r = route == null ? "" : route.toLowerCase(Locale.ROOT);
        if (r.contains("download") || r.contains("/read") || r.contains("readfile")
                || r.contains("getfile") || r.contains("file/get") || r.contains("/view/")
                || r.contains("preview") || r.endsWith("/file") || r.contains("/files/")) {
            if (r.contains("upload") || r.contains("multipart")) {
                return false;
            }
            return true;
        }
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (q.isBlank()) {
            return false;
        }
        if (r.contains("upload") || r.contains("multipart")) {
            return false;
        }
        for (String pair : q.split("&", -1)) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
            if ("path".equals(name) || "filepath".equals(name) || "filename".equals(name)
                    || "file_path".equals(name) || "dir".equals(name) || "directory".equals(name)
                    || "resource".equals(name) || "res".equals(name)) {
                return true;
            }
        }
        return false;
    }

    static String ensureTraversalReadQuery(String query, boolean fileRead) {
        if (!fileRead) {
            return query == null ? "" : query;
        }
        String q = query == null ? "" : query.trim();
        if (q.isBlank()) {
            return "path=../veyrion-read.txt";
        }
        String lower = q.toLowerCase(Locale.ROOT);
        if (lower.contains("path=") || lower.contains("filepath=") || lower.contains("filename=")
                || lower.contains("file=") || lower.contains("name=") || lower.contains("dir=")) {
            return q;
        }
        return q + "&path=../veyrion-read.txt";
    }

    static boolean looksFormUrlEncoded(String route, String query) {
        String r = route == null ? "" : route.toLowerCase(Locale.ROOT);
        if (r.contains("login") || r.contains("signin") || r.contains("/form")
                || r.contains("submit") || r.endsWith("/save") || r.contains("/save/")
                || r.contains("urlencoded") || r.contains("dologin")) {
            return true;
        }
        if (r.contains("json") || r.contains("graphql") || r.contains("api/v")) {
            return false;
        }
        String q = query == null ? "" : query.toLowerCase(Locale.ROOT);
        if (q.isBlank()) {
            return false;
        }
        if (q.contains("jdbcurl=") || q.contains("driverclass") || q.contains("driver=")) {
            return false;
        }
        for (String pair : q.split("&", -1)) {
            int eq = pair.indexOf('=');
            String name = (eq < 0 ? pair : pair.substring(0, eq)).trim();
            if ("username".equals(name) || "password".equals(name) || "passwd".equals(name)
                    || "csrf".equals(name) || "token".equals(name) || "rememberme".equals(name)) {
                return true;
            }
        }
        return false;
    }
}
