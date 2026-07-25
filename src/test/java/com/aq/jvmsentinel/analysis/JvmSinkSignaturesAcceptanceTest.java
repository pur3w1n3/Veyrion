package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.LinkedHashMap;
import java.util.Map;

/** Representative owner-qualified rules and false-positive guards. */
public final class JvmSinkSignaturesAcceptanceTest {
    public static void main(String[] args) {
        Map<Target, String> expected = new LinkedHashMap<>();
        expected.put(new Target("java.lang.Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"), "COMMAND");
        expected.put(new Target("java.io.ObjectInputStream", "readObject", "()Ljava/lang/Object;"), "DESERIALIZATION");
        expected.put(new Target("com.thoughtworks.xstream.XStream", "fromXML",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "DESERIALIZATION");
        expected.put(new Target("org.yaml.snakeyaml.Yaml", "load",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "DESERIALIZATION");
        expected.put(new Target("org.mvel2.MVEL", "eval",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "EXPRESSION");
        expected.put(new Target("org.springframework.expression.Expression", "getValue",
                "()Ljava/lang/Object;"), "EXPRESSION");
        expected.put(new Target("freemarker.template.Template", "process",
                "(Ljava/lang/Object;Ljava/io/Writer;)V"), "TEMPLATE");
        expected.put(new Target("javax.naming.InitialContext", "lookup",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "JNDI");
        expected.put(new Target("java.lang.reflect.Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), "REFLECTION");
        expected.put(new Target("java.sql.Statement", "executeQuery",
                "(Ljava/lang/String;)Ljava/sql/ResultSet;"), "SQL");
        expected.put(new Target("org.bson.Document", "parse",
                "(Ljava/lang/String;)Lorg/bson/Document;"), "NOSQL");
        expected.put(new Target("redis.clients.jedis.Jedis", "eval",
                "(Ljava/lang/String;Ljava/util/List;Ljava/util/List;)Ljava/lang/Object;"), "NOSQL");
        expected.put(new Target("javax.naming.directory.DirContext", "search",
                "(Ljava/lang/String;Ljava/lang/String;Ljavax/naming/directory/SearchControls;)"
                        + "Ljavax/naming/NamingEnumeration;"), "LDAP");
        expected.put(new Target("javax.xml.parsers.DocumentBuilder", "parse",
                "(Ljava/io/InputStream;)Lorg/w3c/dom/Document;"), "XML");
        expected.put(new Target("javax.xml.transform.TransformerFactory", "newTransformer",
                "(Ljavax/xml/transform/Source;)Ljavax/xml/transform/Transformer;"), "XSLT");
        expected.put(new Target("java.nio.file.Files", "readString",
                "(Ljava/nio/file/Path;)Ljava/lang/String;"), "FILE_READ");
        expected.put(new Target("java.nio.file.Files", "writeString",
                "(Ljava/nio/file/Path;Ljava/lang/CharSequence;)Ljava/nio/file/Path;"), "FILE_WRITE");
        expected.put(new Target("java.net.URL", "openConnection",
                "()Ljava/net/URLConnection;"), "SSRF");
        expected.put(new Target("org.springframework.web.client.RestTemplate", "exchange",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "SSRF");
        expected.put(new Target("jakarta.servlet.http.HttpServletResponse", "sendRedirect",
                "(Ljava/lang/String;)V"), "REDIRECT");
        expected.put(new Target("io.jsonwebtoken.JwtParser", "parseClaimsJws",
                "(Ljava/lang/String;)Lio/jsonwebtoken/Jws;"), "JWT");
        expected.put(new Target("com.nimbusds.jwt.SignedJWT", "parse",
                "(Ljava/lang/String;)Lcom/nimbusds/jwt/SignedJWT;"), "JWT");

        int ordinal = 0;
        for (Map.Entry<Target, String> entry : expected.entrySet()) {
            JvmSinkSignatures.Match match = JvmSinkSignatures.match(edge(
                    "app.Controller", "handler", entry.getKey(), ++ordinal));
            check(match != null && entry.getValue().equals(match.category()),
                    entry.getKey() + " should map to " + entry.getValue());
        }

        check(JvmSinkSignatures.match(edge("app.Controller", "handler",
                        new Target("java.lang.String", "parse", "(Ljava/lang/String;)Ljava/lang/String;"), 100)) == null,
                "generic parse method must not match");
        check(JvmSinkSignatures.match(edge("app.Controller", "handler",
                        new Target("com.example.Executor", "execute", "()V"), 101)) == null,
                "generic execute method must not match");
        check(JvmSinkSignatures.match(edge("org.springframework.boot.loader.NoisyLauncher", "launch",
                        new Target("java.lang.Runtime", "exec",
                                "(Ljava/lang/String;)Ljava/lang/Process;"), 102)) == null,
                "Spring Boot launcher infrastructure is excluded");
        check(JvmSinkSignatures.match(new BytecodeFactIndex.CallEdge(
                        "app.Controller", "lambda", "()V", "<dynamic>", "run", "()V",
                        BytecodeFactIndex.EdgeKind.UNRESOLVED, "dynamic",
                        evidence("app.Controller", "lambda", 103))) == null,
                "unresolved dynamic targets are never classified by a concrete owner rule");
        System.out.println("JvmSinkSignaturesAcceptanceTest: PASS");
    }

    private static BytecodeFactIndex.CallEdge edge(
            String caller, String method, Target target, int ordinal) {
        return new BytecodeFactIndex.CallEdge(caller, method, "()V",
                target.owner(), target.name(), target.descriptor(),
                BytecodeFactIndex.EdgeKind.DIRECT, "test symbolic edge",
                evidence(caller, method, ordinal));
    }

    private static BytecodeFactIndex.InstructionEvidence evidence(
            String caller, String method, int ordinal) {
        return new BytecodeFactIndex.InstructionEvidence(caller, method, "()V", ordinal, ordinal);
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private record Target(String owner, String name, String descriptor) {
    }
}
