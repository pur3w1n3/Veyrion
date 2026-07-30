package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.AcceptanceAssertions;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Representative owner-qualified rules, multi-kind labels, and false-positive guards. */
public final class JvmSinkSignaturesAcceptanceTest {
    public static void main(String[] args) {
        Map<Target, String> expectedPrimary = new LinkedHashMap<>();
        expectedPrimary.put(new Target("java.lang.Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"), "COMMAND");
        expectedPrimary.put(new Target("java.io.ObjectInputStream", "readObject", "()Ljava/lang/Object;"), "DESERIALIZATION");
        expectedPrimary.put(new Target("com.thoughtworks.xstream.XStream", "fromXML",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "DESERIALIZATION");
        expectedPrimary.put(new Target("org.yaml.snakeyaml.Yaml", "load",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "DESERIALIZATION");
        expectedPrimary.put(new Target("com.google.gson.Gson", "fromJson",
                "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"), "DESERIALIZATION");
        expectedPrimary.put(new Target("org.mvel2.MVEL", "eval",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "EXPRESSION");
        expectedPrimary.put(new Target("org.springframework.expression.Expression", "getValue",
                "()Ljava/lang/Object;"), "EXPRESSION");
        expectedPrimary.put(new Target("javax.el.ValueExpression", "getValue",
                "(Ljavax/el/ELContext;)Ljava/lang/Object;"), "EXPRESSION");
        expectedPrimary.put(new Target("freemarker.template.Template", "process",
                "(Ljava/lang/Object;Ljava/io/Writer;)V"), "TEMPLATE");
        expectedPrimary.put(new Target("org.thymeleaf.TemplateEngine", "process",
                "(Ljava/lang/String;Lorg/thymeleaf/context/IContext;)Ljava/lang/String;"), "TEMPLATE");
        expectedPrimary.put(new Target("javax.naming.InitialContext", "lookup",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "JNDI");
        expectedPrimary.put(new Target("java.lang.reflect.Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), "REFLECTION");
        expectedPrimary.put(new Target("java.sql.Statement", "executeQuery",
                "(Ljava/lang/String;)Ljava/sql/ResultSet;"), "SQL");
        expectedPrimary.put(new Target("org.bson.Document", "parse",
                "(Ljava/lang/String;)Lorg/bson/Document;"), "NOSQL");
        expectedPrimary.put(new Target("redis.clients.jedis.Jedis", "eval",
                "(Ljava/lang/String;Ljava/util/List;Ljava/util/List;)Ljava/lang/Object;"), "NOSQL");
        expectedPrimary.put(new Target("javax.naming.directory.DirContext", "search",
                "(Ljava/lang/String;Ljava/lang/String;Ljavax/naming/directory/SearchControls;)"
                        + "Ljavax/naming/NamingEnumeration;"), "LDAP");
        expectedPrimary.put(new Target("javax.xml.parsers.DocumentBuilder", "parse",
                "(Ljava/io/InputStream;)Lorg/w3c/dom/Document;"), "XML");
        expectedPrimary.put(new Target("javax.xml.transform.TransformerFactory", "newTransformer",
                "(Ljavax/xml/transform/Source;)Ljavax/xml/transform/Transformer;"), "XSLT");
        expectedPrimary.put(new Target("java.nio.file.Files", "readString",
                "(Ljava/nio/file/Path;)Ljava/lang/String;"), "FILE_READ");
        expectedPrimary.put(new Target("java.nio.file.Files", "writeString",
                "(Ljava/nio/file/Path;Ljava/lang/CharSequence;)Ljava/nio/file/Path;"), "FILE_WRITE");
        expectedPrimary.put(new Target("java.net.URL", "openConnection",
                "()Ljava/net/URLConnection;"), "SSRF");
        expectedPrimary.put(new Target("org.springframework.web.client.RestTemplate", "exchange",
                "(Ljava/lang/String;)Ljava/lang/Object;"), "SSRF");
        expectedPrimary.put(new Target("jakarta.servlet.http.HttpServletResponse", "sendRedirect",
                "(Ljava/lang/String;)V"), "REDIRECT");
        expectedPrimary.put(new Target("io.jsonwebtoken.JwtParser", "parseClaimsJws",
                "(Ljava/lang/String;)Lio/jsonwebtoken/Jws;"), "JWT");
        expectedPrimary.put(new Target("com.nimbusds.jwt.SignedJWT", "parse",
                "(Ljava/lang/String;)Lcom/nimbusds/jwt/SignedJWT;"), "JWT");
        expectedPrimary.put(new Target("org.flowable.engine.RepositoryService", "createDeployment",
                "()Lorg/flowable/engine/repository/DeploymentBuilder;"), "BPMN_DEPLOY");
        expectedPrimary.put(new Target("org.flowable.engine.repository.DeploymentBuilder", "deploy",
                "()Lorg/flowable/engine/repository/Deployment;"), "BPMN_DEPLOY");
        expectedPrimary.put(new Target("org.flowable.engine.repository.DeploymentBuilder", "addBytes",
                "(Ljava/lang/String;[B)Lorg/flowable/engine/repository/DeploymentBuilder;"),
                "BPMN_DEPLOY");
        expectedPrimary.put(new Target("org.activiti.engine.RuntimeService", "startProcessInstanceByKey",
                "(Ljava/lang/String;)Lorg/activiti/engine/runtime/ProcessInstance;"), "BPMN_EXEC");

        int ordinal = 0;
        for (Map.Entry<Target, String> entry : expectedPrimary.entrySet()) {
            JvmSinkSignatures.Match match = JvmSinkSignatures.match(edge(
                    "app.Controller", "handler", entry.getKey(), ++ordinal));
            check(match != null && entry.getValue().equals(match.category()),
                    entry.getKey() + " should map to " + entry.getValue());
        }

        JvmSinkSignatures.Match jdbcUrl = JvmSinkSignatures.match(edge(
                "app.Controller", "handler",
                new Target("java.sql.DriverManager", "getConnection",
                        "(Ljava/lang/String;)Ljava/sql/Connection;"), ++ordinal));
        check(jdbcUrl != null, "DriverManager.getConnection must match");
        check(jdbcUrl.kinds().equals(List.of("SSRF", "COMMAND", "CLASS_LOADING")),
                "JDBC URL kinds must be SSRF+COMMAND+CLASS_LOADING, not SQL/CLASS_LOADING-only: "
                        + jdbcUrl.kinds());
        check("SSRF".equals(jdbcUrl.category()), "JDBC URL primary kind is SSRF");

        JvmSinkSignatures.Match jndi = JvmSinkSignatures.match(edge(
                "app.Controller", "handler",
                new Target("javax.naming.InitialContext", "lookup",
                        "(Ljava/lang/String;)Ljava/lang/Object;"), ++ordinal));
        check(jndi != null && jndi.kinds().containsAll(Set.of("JNDI", "CLASS_LOADING", "DESERIALIZATION")),
                "JNDI lookup must carry CLASS_LOADING/DESERIALIZATION side-effects: " + jndi.kinds());

        JvmSinkSignatures.Match urlLoader = JvmSinkSignatures.match(edge(
                "app.Controller", "handler",
                new Target("java.net.URLClassLoader", "loadClass",
                        "(Ljava/lang/String;)Ljava/lang/Class;"), ++ordinal));
        check(urlLoader != null && urlLoader.kinds().equals(List.of("CLASS_LOADING", "SSRF")),
                "URLClassLoader must be CLASS_LOADING+SSRF: " + urlLoader.kinds());

        JvmSinkSignatures.Match script = JvmSinkSignatures.match(edge(
                "app.Controller", "handler",
                new Target("javax.script.ScriptEngine", "eval",
                        "(Ljava/lang/String;)Ljava/lang/Object;"), ++ordinal));
        check(script != null && script.kinds().equals(List.of("EXPRESSION", "COMMAND")),
                "ScriptEngine.eval must be EXPRESSION+COMMAND: " + script.kinds());

        JvmSinkSignatures.Match hikari = JvmSinkSignatures.match(edge(
                "app.Controller", "handler",
                new Target("com.zaxxer.hikari.HikariConfig", "setJdbcUrl",
                        "(Ljava/lang/String;)V"), ++ordinal));
        check(hikari != null && hikari.kinds().containsAll(Set.of("SSRF", "COMMAND", "CLASS_LOADING")),
                "Hikari setJdbcUrl must share JDBC URL multi-kind set: " + hikari.kinds());

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
        AcceptanceAssertions.record();
        if (!value) throw new AssertionError(message);
    }

    private record Target(String owner, String name, String descriptor) {
    }
}
