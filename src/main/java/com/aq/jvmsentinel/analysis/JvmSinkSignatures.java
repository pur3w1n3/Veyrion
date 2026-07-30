package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.List;
import java.util.Set;

/**
 * 源自项目 Java audit checklist 的高信号 JVM invocation catalog。
 *
 * <p>匹配仅表示 bytecode 中存在敏感 API 调用。不
 * 建立 attacker control、runtime reachability、unsafe configuration 或
 * exploitability 签名。{@code parse}、{@code read}、
 * {@code execute} 等宽泛 keyword 刻意在无 owner constraint 时不匹配。
 *
 * <p>Kind 按 primary-first 排序。单 call site 可携带多种 security
 * effect（如 JDBC URL → SSRF + COMMAND + CLASS_LOADING）。需要单 label 的消费者用 {@link Match#category()}；完整集合用 {@link Match#kinds()}。
 */
final class JvmSinkSignatures {
    private static final List<Rule> RULES = List.of(
            exact("runtime-exec", "COMMAND", "java.lang.Runtime", 0.98, "exec"),
            exact("process-builder-start", "COMMAND", "java.lang.ProcessBuilder", 0.98, "start"),
            exact("process-impl-start", "COMMAND", "java.lang.ProcessImpl", 0.96, "start"),
            exact("native-library-load", "NATIVE_CODE", "java.lang.System", 0.97, "load", "loadLibrary"),

            exact("java-deserialization", "DESERIALIZATION", "java.io.ObjectInputStream", 0.96,
                    "readObject", "readUnshared"),
            exact("xml-decoder", "DESERIALIZATION", "java.beans.XMLDecoder", 0.96, "readObject"),
            exact("signed-object", "DESERIALIZATION", "java.security.SignedObject", 0.90, "getObject"),
            exact("sealed-object", "DESERIALIZATION", "javax.crypto.SealedObject", 0.90, "getObject"),
            exact("jms-object-message", "DESERIALIZATION", "javax.jms.ObjectMessage", 0.90, "getObject"),
            exact("jakarta-jms-object-message", "DESERIALIZATION", "jakarta.jms.ObjectMessage", 0.90, "getObject"),
            exactKinds("xstream-from-xml", List.of("DESERIALIZATION", "CLASS_LOADING"),
                    "com.thoughtworks.xstream.XStream", 0.90, "fromXML"),
            exactKinds("snakeyaml-load", List.of("DESERIALIZATION", "CLASS_LOADING"),
                    "org.yaml.snakeyaml.Yaml", 0.82, "load", "loadAll", "loadAs"),
            exactKinds("hessian-read-object", List.of("DESERIALIZATION", "CLASS_LOADING"),
                    "com.caucho.hessian.io.HessianInput", 0.92, "readObject"),
            exactKinds("hessian2-read-object", List.of("DESERIALIZATION", "CLASS_LOADING"),
                    "com.caucho.hessian.io.Hessian2Input", 0.92, "readObject"),
            exact("burlap-read-object", "DESERIALIZATION", "com.caucho.burlap.io.BurlapInput", 0.92,
                    "readObject"),
            exact("kryo-read-object", "DESERIALIZATION", "com.esotericsoftware.kryo.Kryo", 0.86,
                    "readClassAndObject", "readObject"),
            exact("fst-as-object", "DESERIALIZATION", "org.nustaq.serialization.FSTConfiguration", 0.90,
                    "asObject"),
            prefix("fury-deserialize", "DESERIALIZATION", "org.apache.fury.", 0.88,
                    "deserialize", "deserializeJavaObject"),
            exact("spring-serialization-utils", "DESERIALIZATION",
                    "org.springframework.util.SerializationUtils", 0.94, "deserialize"),
            exact("commons-lang-serialization-utils", "DESERIALIZATION",
                    "org.apache.commons.lang.SerializationUtils", 0.94, "deserialize"),
            exact("commons-lang3-serialization-utils", "DESERIALIZATION",
                    "org.apache.commons.lang3.SerializationUtils", 0.94, "deserialize"),
            exactKinds("fastjson-parse", List.of("DESERIALIZATION", "CLASS_LOADING"),
                    "com.alibaba.fastjson.JSON", 0.74,
                    "parse", "parseObject", "parseArray", "toJavaObject"),
            exactKinds("fastjson2-parse", List.of("DESERIALIZATION", "CLASS_LOADING"),
                    "com.alibaba.fastjson2.JSON", 0.72,
                    "parse", "parseObject", "parseArray"),
            exact("jackson-read-value", "DESERIALIZATION", "com.fasterxml.jackson.databind.ObjectMapper", 0.70,
                    "readValue", "treeToValue", "convertValue"),
            exact("json-io-read", "DESERIALIZATION", "com.cedarsoftware.util.io.JsonReader", 0.84,
                    "jsonToJava", "readObject"),
            exact("gson-from-json", "DESERIALIZATION", "com.google.gson.Gson", 0.72, "fromJson"),
            exact("rome-synd-feed", "DESERIALIZATION", "com.rometools.rome.io.SyndFeedInput", 0.86,
                    "build"),
            exact("genson-deserialize", "DESERIALIZATION", "com.owlike.genson.Genson", 0.80,
                    "deserialize"),
            exact("flexjson-deserialize", "DESERIALIZATION", "flexjson.JSONDeserializer", 0.80,
                    "deserialize"),
            exact("jodd-json-parse", "DESERIALIZATION", "jodd.json.JsonParser", 0.80, "parse"),
            exactKinds("templates-impl-trigger", List.of("DESERIALIZATION", "CLASS_LOADING"),
                    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", 0.94,
                    "newTransformer", "getOutputProperties"),

            exactKinds("jdk-script-eval", List.of("EXPRESSION", "COMMAND"),
                    "javax.script.ScriptEngine", 0.96, "eval"),
            exactKinds("jakarta-script-eval", List.of("EXPRESSION", "COMMAND"),
                    "jakarta.script.ScriptEngine", 0.96, "eval"),
            exact("java-beans-expression", "EXPRESSION", "java.beans.Expression", 0.90, "getValue"),
            exact("javax-el-factory", "EXPRESSION", "javax.el.ExpressionFactory", 0.88,
                    "createValueExpression", "createMethodExpression"),
            exact("javax-el-value", "EXPRESSION", "javax.el.ValueExpression", 0.90, "getValue"),
            exact("jakarta-el-factory", "EXPRESSION", "jakarta.el.ExpressionFactory", 0.88,
                    "createValueExpression", "createMethodExpression"),
            exact("jakarta-el-value", "EXPRESSION", "jakarta.el.ValueExpression", 0.90, "getValue"),
            exact("spring-expression-parse", "EXPRESSION",
                    "org.springframework.expression.spel.standard.SpelExpressionParser", 0.74,
                    "parseExpression"),
            exact("spring-expression-evaluate", "EXPRESSION",
                    "org.springframework.expression.Expression", 0.78, "getValue", "getValueType"),
            exactKinds("hutool-script-eval", List.of("EXPRESSION", "COMMAND"),
                    "cn.hutool.script.ScriptUtil", 0.96, "eval"),
            exact("aviator-execute", "EXPRESSION", "com.googlecode.aviator.AviatorEvaluator", 0.92,
                    "execute", "exec"),
            exact("ql-express", "EXPRESSION", "com.ql.util.express.ExpressRunner", 0.92, "execute"),
            exact("ognl-evaluate", "EXPRESSION", "ognl.Ognl", 0.94, "getValue", "setValue"),
            exact("mvel-evaluate", "EXPRESSION", "org.mvel2.MVEL", 0.94,
                    "eval", "evalToString", "executeExpression"),
            exactKinds("groovy-evaluate", List.of("EXPRESSION", "COMMAND"),
                    "groovy.lang.GroovyShell", 0.94, "evaluate", "parse"),
            exactKinds("groovy-class-loader", List.of("CLASS_LOADING", "EXPRESSION", "COMMAND"),
                    "groovy.lang.GroovyClassLoader", 0.94, "parseClass"),
            exactKinds("jython-exec", List.of("EXPRESSION", "COMMAND"),
                    "org.python.util.PythonInterpreter", 0.96, "exec", "eval"),
            exactKinds("jruby-scriptlet", List.of("EXPRESSION", "COMMAND"),
                    "org.jruby.embed.ScriptingContainer", 0.96, "runScriptlet"),
            exactKinds("beanshell-eval", List.of("EXPRESSION", "COMMAND"),
                    "bsh.Interpreter", 0.96, "eval", "source"),
            prefix("jexl-evaluate", "EXPRESSION", "org.apache.commons.jexl", 0.88, "evaluate"),
            prefixKinds("janino-cook", List.of("EXPRESSION", "COMMAND", "CLASS_LOADING"),
                    "org.codehaus.janino.", 0.94, "cook", "evaluate"),

            exact("velocity-evaluate", "TEMPLATE", "org.apache.velocity.app.VelocityEngine", 0.90, "evaluate"),
            exact("velocity-static-evaluate", "TEMPLATE", "org.apache.velocity.app.Velocity", 0.90, "evaluate"),
            exact("freemarker-process", "TEMPLATE", "freemarker.template.Template", 0.76, "process"),
            exact("thymeleaf-process", "TEMPLATE", "org.thymeleaf.TemplateEngine", 0.78, "process"),
            exact("jinjava-render", "TEMPLATE", "com.hubspot.jinjava.Jinjava", 0.88, "render"),
            exact("rythm-render", "TEMPLATE", "org.rythmengine.Rythm", 0.88, "render"),
            prefix("pebble-evaluate", "TEMPLATE", "io.pebbletemplates.pebble.", 0.82, "evaluate"),
            prefix("beetl-render", "TEMPLATE", "org.beetl.", 0.82, "render"),
            exact("handlebars-inline", "TEMPLATE", "com.github.jknack.handlebars.Handlebars", 0.74,
                    "compileInline"),

            // JNDI lookup 常隐含 remote class loading / deserialization 副作用。
            exactKinds("jndi-initial-context", List.of("JNDI", "CLASS_LOADING", "DESERIALIZATION"),
                    "javax.naming.InitialContext", 0.94, "lookup", "doLookup"),
            exactKinds("jndi-context", List.of("JNDI", "CLASS_LOADING", "DESERIALIZATION"),
                    "javax.naming.Context", 0.90, "lookup", "bind", "rebind"),
            prefixKinds("ldap-context-lookup", List.of("JNDI", "CLASS_LOADING"),
                    "javax.naming.ldap.", 0.92, "lookup"),
            exactKinds("rmi-registry-lookup", List.of("JNDI", "CLASS_LOADING", "DESERIALIZATION"),
                    "java.rmi.registry.Registry", 0.90, "lookup"),
            exactKinds("jdbc-rowset-datasource", List.of("JNDI", "CLASS_LOADING", "DESERIALIZATION"),
                    "javax.sql.rowset.BaseRowSet", 0.90, "setDataSourceName"),
            exactKinds("sun-jdbc-rowset-datasource", List.of("JNDI", "CLASS_LOADING", "DESERIALIZATION"),
                    "com.sun.rowset.JdbcRowSetImpl", 0.94, "setDataSourceName", "setAutoCommit"),

            exact("class-for-name", "CLASS_LOADING", "java.lang.Class", 0.86, "forName", "newInstance"),
            exact("class-loader", "CLASS_LOADING", "java.lang.ClassLoader", 0.92,
                    "loadClass", "defineClass", "findClass"),
            // URLClassLoader 从 URL 加载 bytecode → CLASS_LOADING 主、SSRF 次。
            exactKinds("url-class-loader", List.of("CLASS_LOADING", "SSRF"),
                    "java.net.URLClassLoader", 0.92, "loadClass", "findClass", "<init>"),
            exact("unsafe-define-class", "CLASS_LOADING", "sun.misc.Unsafe", 0.96,
                    "defineClass", "defineAnonymousClass"),
            exact("method-invoke", "REFLECTION", "java.lang.reflect.Method", 0.80, "invoke"),
            exact("constructor-new-instance", "REFLECTION", "java.lang.reflect.Constructor", 0.80, "newInstance"),

            exact("jdbc-statement", "SQL", "java.sql.Statement", 0.88,
                    "execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch"),
            // 可控 JDBC URL：network fetch（SSRF）、driver feature RCE（COMMAND）、driver/class load。
            exactKinds("jdbc-connection-url", List.of("SSRF", "COMMAND", "CLASS_LOADING"),
                    "java.sql.DriverManager", 0.90, "getConnection"),
            exactKinds("jdbc-driver-connect", List.of("SSRF", "COMMAND", "CLASS_LOADING"),
                    "java.sql.Driver", 0.88, "connect"),
            exactKinds("spring-driver-manager-set-url", List.of("SSRF", "COMMAND", "CLASS_LOADING"),
                    "org.springframework.jdbc.datasource.DriverManagerDataSource", 0.88, "setUrl"),
            exactKinds("hikari-set-jdbc-url", List.of("SSRF", "COMMAND", "CLASS_LOADING"),
                    "com.zaxxer.hikari.HikariConfig", 0.88, "setJdbcUrl"),
            exactKinds("hikari-ds-set-jdbc-url", List.of("SSRF", "COMMAND", "CLASS_LOADING"),
                    "com.zaxxer.hikari.HikariDataSource", 0.88, "setJdbcUrl"),
            exactKinds("druid-set-url", List.of("SSRF", "COMMAND", "CLASS_LOADING"),
                    "com.alibaba.druid.pool.DruidDataSource", 0.88, "setUrl"),
            exactKinds("dbcp2-set-url", List.of("SSRF", "COMMAND", "CLASS_LOADING"),
                    "org.apache.commons.dbcp2.BasicDataSource", 0.88, "setUrl"),
            exactKinds("tomcat-dbcp-set-url", List.of("SSRF", "COMMAND", "CLASS_LOADING"),
                    "org.apache.tomcat.dbcp.dbcp2.BasicDataSource", 0.88, "setUrl"),
            exact("jpa-query", "SQL", "javax.persistence.EntityManager", 0.78,
                    "createQuery", "createNativeQuery"),
            exact("jakarta-jpa-query", "SQL", "jakarta.persistence.EntityManager", 0.78,
                    "createQuery", "createNativeQuery"),
            exact("hibernate-session-query", "SQL", "org.hibernate.Session", 0.78,
                    "createQuery", "createNativeQuery"),
            exact("hibernate-shared-session-query", "SQL", "org.hibernate.SharedSessionContract", 0.78,
                    "createQuery", "createNativeQuery"),
            exact("spring-jdbc-template", "SQL", "org.springframework.jdbc.core.JdbcTemplate", 0.76,
                    "execute", "query", "queryForObject", "update", "batchUpdate"),
            exact("spring-named-jdbc-template", "SQL",
                    "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate", 0.76,
                    "execute", "query", "queryForObject", "update", "batchUpdate"),
            exact("mongodb-document-parse", "NOSQL", "org.bson.Document", 0.78, "parse"),
            exact("mongodb-collection", "NOSQL", "com.mongodb.client.MongoCollection", 0.78,
                    "find", "aggregate", "mapReduce"),
            exact("jedis-script", "NOSQL", "redis.clients.jedis.Jedis", 0.90, "eval", "evalsha"),
            exact("ldap-search", "LDAP", "javax.naming.directory.DirContext", 0.88, "search"),
            exact("ldap-search-context", "LDAP", "javax.naming.ldap.LdapContext", 0.88, "search"),
            exact("xpath-evaluate", "XPATH", "javax.xml.xpath.XPath", 0.84, "evaluate"),
            exact("xpath-expression", "XPATH", "javax.xml.xpath.XPathExpression", 0.84, "evaluate"),
            exact("dom-document-parse", "XML", "javax.xml.parsers.DocumentBuilder", 0.82, "parse"),
            exact("sax-parser", "XML", "javax.xml.parsers.SAXParser", 0.82, "parse"),
            exact("xml-reader", "XML", "org.xml.sax.XMLReader", 0.82, "parse"),
            exact("dom4j-sax-reader", "XML", "org.dom4j.io.SAXReader", 0.82, "read"),
            exact("xslt-transformer-factory", "XSLT", "javax.xml.transform.TransformerFactory", 0.88,
                    "newTransformer", "newTemplates"),

            exact("file-input-stream", "FILE_READ", "java.io.FileInputStream", 0.84, "<init>"),
            exact("file-reader", "FILE_READ", "java.io.FileReader", 0.84, "<init>"),
            exact("random-access-file", "FILE_READ", "java.io.RandomAccessFile", 0.78, "<init>"),
            exact("nio-file-read", "FILE_READ", "java.nio.file.Files", 0.86,
                    "readAllBytes", "readString", "lines", "newBufferedReader", "newInputStream"),
            exact("commons-io-file-read", "FILE_READ", "org.apache.commons.io.FileUtils", 0.84,
                    "readFileToString", "readFileToByteArray", "openInputStream"),
            exact("file-output-stream", "FILE_WRITE", "java.io.FileOutputStream", 0.88, "<init>"),
            exact("file-writer", "FILE_WRITE", "java.io.FileWriter", 0.88, "<init>"),
            exact("nio-file-write", "FILE_WRITE", "java.nio.file.Files", 0.88,
                    "write", "writeString", "newBufferedWriter", "newOutputStream", "copy", "move"),
            exact("commons-io-file-write", "FILE_WRITE", "org.apache.commons.io.FileUtils", 0.88,
                    "write", "writeStringToFile", "writeByteArrayToFile",
                    "copyFile", "copyFileToDirectory", "copyDirectory",
                    "moveFile", "moveDirectory"),
            exact("multipart-transfer", "FILE_WRITE", "org.springframework.web.multipart.MultipartFile", 0.90,
                    "transferTo"),
            exact("file-delete", "FILE_DELETE", "java.io.File", 0.90, "delete", "deleteOnExit"),
            exact("nio-file-delete", "FILE_DELETE", "java.nio.file.Files", 0.92, "delete", "deleteIfExists"),
            exact("commons-io-delete", "FILE_DELETE", "org.apache.commons.io.FileUtils", 0.92,
                    "forceDelete", "deleteDirectory"),
            exact("archive-entry", "ARCHIVE", "java.util.zip.ZipInputStream", 0.70, "getNextEntry"),
            prefix("commons-compress-entry", "ARCHIVE", "org.apache.commons.compress.archivers.", 0.70,
                    "getNextEntry", "getNextTarEntry"),

            descriptor("jdk-url-open", "SSRF", "java.net.URL", 0.88, null,
                    Set.of("openConnection", "openStream")),
            exact("jdk-http-client", "SSRF", "java.net.http.HttpClient", 0.88, "send", "sendAsync"),
            exact("apache-http-client", "SSRF", "org.apache.http.client.HttpClient", 0.88, "execute"),
            exact("apache-closeable-http-client", "SSRF",
                    "org.apache.http.impl.client.CloseableHttpClient", 0.88, "execute"),
            exact("okhttp-call", "SSRF", "okhttp3.Call", 0.88, "execute", "enqueue"),
            exact("spring-rest-template", "SSRF", "org.springframework.web.client.RestTemplate", 0.86,
                    "getForObject", "getForEntity", "postForObject", "postForEntity", "exchange", "execute"),
            exact("spring-webclient", "SSRF", "org.springframework.web.reactive.function.client.WebClient", 0.86,
                    "create", "mutate"),
            descriptor("imageio-url", "SSRF", "javax.imageio.ImageIO", 0.86, "(Ljava/net/URL;",
                    Set.of("read")),
            exact("servlet-redirect", "REDIRECT", "javax.servlet.http.HttpServletResponse", 0.84,
                    "sendRedirect"),
            exact("jakarta-servlet-redirect", "REDIRECT", "jakarta.servlet.http.HttpServletResponse", 0.84,
                    "sendRedirect"),

            // JWT / token API — 仅 presence；非 missing verification 或 exploitability 证明。
            exact("jjwt-parser-parse", "JWT", "io.jsonwebtoken.JwtParser", 0.88,
                    "parse", "parseClaimsJws", "parseClaimsJwt", "parseSignedClaims"),
            exact("jjwt-parser-builder", "JWT", "io.jsonwebtoken.JwtParserBuilder", 0.80, "build"),
            exact("jjwt-jwts-parser", "JWT", "io.jsonwebtoken.Jwts", 0.82, "parser", "parserBuilder"),
            exact("nimbus-signed-jwt-parse", "JWT", "com.nimbusds.jwt.SignedJWT", 0.88, "parse"),
            exact("nimbus-jwt-processor", "JWT", "com.nimbusds.jwt.proc.DefaultJWTProcessor", 0.86,
                    "process", "processToClaims"),
            exact("auth0-jwt-decode", "JWT", "com.auth0.jwt.JWT", 0.84, "decode", "require"),
            exact("auth0-jwt-verifier", "JWT", "com.auth0.jwt.interfaces.JWTVerifier", 0.86, "verify"),
            prefix("blade-jwt", "JWT", "org.springblade.core.jwt.", 0.84,
                    "parse", "parseToken", "getToken", "createToken", "createAuthInfo", "parseJWT"),
            prefix("blade-secure-token", "AUTH", "org.springblade.core.secure.", 0.78,
                    "getUser", "getUserId", "getClientId", "parseToken"),

            // BPMN deploy+expression 面 Flowable/Activiti/Camunda（仅 presence）。
            exact("flowable-create-deployment", "BPMN_DEPLOY",
                    "org.flowable.engine.RepositoryService", 0.90, "createDeployment"),
            exact("flowable-deployment-deploy", "BPMN_DEPLOY",
                    "org.flowable.engine.repository.DeploymentBuilder", 0.92,
                    "deploy", "addBytes", "addInputStream", "addClasspathResource", "addString"),
            exact("flowable-delete-deployment", "BPMN_DEPLOY",
                    "org.flowable.engine.RepositoryService", 0.86, "deleteDeployment"),
            exact("flowable-start-process", "BPMN_EXEC",
                    "org.flowable.engine.RuntimeService", 0.88,
                    "startProcessInstanceByKey", "startProcessInstanceById",
                    "startProcessInstanceByMessage"),
            exact("flowable-expression-get-value", "EXPRESSION",
                    "org.flowable.common.engine.api.delegate.Expression", 0.86, "getValue"),
            exact("flowable-scripting-evaluate", "EXPRESSION",
                    "org.flowable.common.engine.impl.scripting.ScriptingEngines", 0.90, "evaluate"),
            exact("activiti-create-deployment", "BPMN_DEPLOY",
                    "org.activiti.engine.RepositoryService", 0.90, "createDeployment"),
            exact("activiti-deployment-deploy", "BPMN_DEPLOY",
                    "org.activiti.engine.repository.DeploymentBuilder", 0.92,
                    "deploy", "addBytes", "addInputStream", "addClasspathResource", "addString"),
            exact("activiti-start-process", "BPMN_EXEC",
                    "org.activiti.engine.RuntimeService", 0.88,
                    "startProcessInstanceByKey", "startProcessInstanceById"),
            exact("camunda-create-deployment", "BPMN_DEPLOY",
                    "org.camunda.bpm.engine.RepositoryService", 0.90, "createDeployment"),
            exact("camunda-deployment-deploy", "BPMN_DEPLOY",
                    "org.camunda.bpm.engine.repository.DeploymentBuilder", 0.92,
                    "deploy", "addBytes", "addInputStream", "addClasspathResource", "addString"),
            exact("camunda-start-process", "BPMN_EXEC",
                    "org.camunda.bpm.engine.RuntimeService", 0.88,
                    "startProcessInstanceByKey", "startProcessInstanceById")
    );

    private JvmSinkSignatures() {
    }

    static Match match(BytecodeFactIndex.CallEdge edge) {
        if (edge == null || edge.kind() == BytecodeFactIndex.EdgeKind.UNRESOLVED) return null;
        // 可执行 Spring Boot archive 在
        // BOOT-INF/classes 外携带 launcher 基础设施。其 class loading、archive I/O 与 URL handler 为
        // 实现机制而非 application sink，此前
        // 对每个 Boot artifact 的结果占主导。
        if (edge.callerOwner().startsWith("org.springframework.boot.loader.")) return null;
        for (Rule rule : RULES) {
            if (rule.matches(edge)) return new Match(rule.id, rule.kinds, rule.confidence);
        }
        return null;
    }

    /**
     * @param kinds ordered primary-first security effect labels for this call site
     */
    record Match(String ruleId, List<String> kinds, double confidence) {
        Match {
            kinds = List.copyOf(kinds);
            if (kinds.isEmpty()) {
                throw new IllegalArgumentException("kinds must not be empty");
            }
        }

        /** Primary kind for single-label consumers. */
        String category() {
            return kinds.get(0);
        }
    }

    private record Rule(String id, List<String> kinds, String owner, boolean ownerPrefix,
                        Set<String> methods, String descriptorPrefix, double confidence) {
        private boolean matches(BytecodeFactIndex.CallEdge edge) {
            boolean ownerMatches = ownerPrefix
                    ? edge.targetOwner().startsWith(owner) : edge.targetOwner().equals(owner);
            return ownerMatches && methods.contains(edge.targetName())
                    && (descriptorPrefix == null || edge.targetDescriptor().startsWith(descriptorPrefix));
        }
    }

    private static Rule exact(String id, String category, String owner, double confidence,
                              String... methods) {
        return exactKinds(id, List.of(category), owner, confidence, methods);
    }

    private static Rule exactKinds(String id, List<String> kinds, String owner, double confidence,
                                   String... methods) {
        return descriptorKinds(id, kinds, owner, confidence, null, Set.of(methods));
    }

    private static Rule prefix(String id, String category, String ownerPrefix, double confidence,
                               String... methods) {
        return prefixKinds(id, List.of(category), ownerPrefix, confidence, methods);
    }

    private static Rule prefixKinds(String id, List<String> kinds, String ownerPrefix, double confidence,
                                    String... methods) {
        return new Rule(id, List.copyOf(kinds), ownerPrefix, true, Set.of(methods), null, confidence);
    }

    private static Rule descriptor(String id, String category, String owner, double confidence,
                                   String descriptorPrefix, Set<String> methods) {
        return descriptorKinds(id, List.of(category), owner, confidence, descriptorPrefix, methods);
    }

    private static Rule descriptorKinds(String id, List<String> kinds, String owner, double confidence,
                                        String descriptorPrefix, Set<String> methods) {
        return new Rule(id, List.copyOf(kinds), owner, false, methods, descriptorPrefix, confidence);
    }
}
