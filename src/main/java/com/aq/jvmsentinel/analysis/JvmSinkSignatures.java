package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.util.List;
import java.util.Set;

/**
 * High-signal JVM invocation catalog derived from the project Java audit checklist.
 *
 * <p>A match means only that a sensitive API call is present in bytecode. It does
 * not establish attacker control, runtime reachability, unsafe configuration, or
 * exploitability. Broad keywords such as {@code parse}, {@code read}, and
 * {@code execute} are deliberately never matched without an owner constraint.
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
            exact("xstream-from-xml", "DESERIALIZATION", "com.thoughtworks.xstream.XStream", 0.90, "fromXML"),
            exact("snakeyaml-load", "DESERIALIZATION", "org.yaml.snakeyaml.Yaml", 0.82,
                    "load", "loadAll", "loadAs"),
            exact("hessian-read-object", "DESERIALIZATION", "com.caucho.hessian.io.HessianInput", 0.92,
                    "readObject"),
            exact("hessian2-read-object", "DESERIALIZATION", "com.caucho.hessian.io.Hessian2Input", 0.92,
                    "readObject"),
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
            exact("fastjson-parse", "DESERIALIZATION", "com.alibaba.fastjson.JSON", 0.74,
                    "parse", "parseObject", "parseArray", "toJavaObject"),
            exact("fastjson2-parse", "DESERIALIZATION", "com.alibaba.fastjson2.JSON", 0.72,
                    "parse", "parseObject", "parseArray"),
            exact("jackson-read-value", "DESERIALIZATION", "com.fasterxml.jackson.databind.ObjectMapper", 0.70,
                    "readValue", "treeToValue", "convertValue"),
            exact("json-io-read", "DESERIALIZATION", "com.cedarsoftware.util.io.JsonReader", 0.84,
                    "jsonToJava", "readObject"),
            exact("templates-impl-trigger", "DESERIALIZATION",
                    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", 0.94,
                    "newTransformer", "getOutputProperties"),

            exact("jdk-script-eval", "EXPRESSION", "javax.script.ScriptEngine", 0.96, "eval"),
            exact("java-beans-expression", "EXPRESSION", "java.beans.Expression", 0.90, "getValue"),
            exact("spring-expression-parse", "EXPRESSION",
                    "org.springframework.expression.spel.standard.SpelExpressionParser", 0.74,
                    "parseExpression"),
            exact("spring-expression-evaluate", "EXPRESSION",
                    "org.springframework.expression.Expression", 0.78, "getValue", "getValueType"),
            exact("hutool-script-eval", "EXPRESSION", "cn.hutool.script.ScriptUtil", 0.96, "eval"),
            exact("aviator-execute", "EXPRESSION", "com.googlecode.aviator.AviatorEvaluator", 0.92,
                    "execute", "exec"),
            exact("ql-express", "EXPRESSION", "com.ql.util.express.ExpressRunner", 0.92, "execute"),
            exact("ognl-evaluate", "EXPRESSION", "ognl.Ognl", 0.94, "getValue", "setValue"),
            exact("mvel-evaluate", "EXPRESSION", "org.mvel2.MVEL", 0.94,
                    "eval", "evalToString", "executeExpression"),
            exact("groovy-evaluate", "EXPRESSION", "groovy.lang.GroovyShell", 0.94, "evaluate", "parse"),
            exact("groovy-class-loader", "CLASS_LOADING", "groovy.lang.GroovyClassLoader", 0.94, "parseClass"),
            exact("jython-exec", "EXPRESSION", "org.python.util.PythonInterpreter", 0.96, "exec", "eval"),
            exact("jruby-scriptlet", "EXPRESSION", "org.jruby.embed.ScriptingContainer", 0.96, "runScriptlet"),
            exact("beanshell-eval", "EXPRESSION", "bsh.Interpreter", 0.96, "eval", "source"),
            prefix("jexl-evaluate", "EXPRESSION", "org.apache.commons.jexl", 0.88, "evaluate"),
            prefix("janino-cook", "EXPRESSION", "org.codehaus.janino.", 0.94, "cook", "evaluate"),

            exact("velocity-evaluate", "TEMPLATE", "org.apache.velocity.app.VelocityEngine", 0.90, "evaluate"),
            exact("velocity-static-evaluate", "TEMPLATE", "org.apache.velocity.app.Velocity", 0.90, "evaluate"),
            exact("freemarker-process", "TEMPLATE", "freemarker.template.Template", 0.76, "process"),
            exact("jinjava-render", "TEMPLATE", "com.hubspot.jinjava.Jinjava", 0.88, "render"),
            exact("rythm-render", "TEMPLATE", "org.rythmengine.Rythm", 0.88, "render"),
            prefix("pebble-evaluate", "TEMPLATE", "io.pebbletemplates.pebble.", 0.82, "evaluate"),
            prefix("beetl-render", "TEMPLATE", "org.beetl.", 0.82, "render"),
            exact("handlebars-inline", "TEMPLATE", "com.github.jknack.handlebars.Handlebars", 0.74,
                    "compileInline"),

            exact("jndi-initial-context", "JNDI", "javax.naming.InitialContext", 0.94, "lookup", "doLookup"),
            exact("jndi-context", "JNDI", "javax.naming.Context", 0.90, "lookup", "bind", "rebind"),
            prefix("ldap-context-lookup", "JNDI", "javax.naming.ldap.", 0.92, "lookup"),
            exact("rmi-registry-lookup", "JNDI", "java.rmi.registry.Registry", 0.90, "lookup"),

            exact("class-for-name", "CLASS_LOADING", "java.lang.Class", 0.86, "forName", "newInstance"),
            exact("class-loader", "CLASS_LOADING", "java.lang.ClassLoader", 0.92,
                    "loadClass", "defineClass", "findClass"),
            exact("url-class-loader", "CLASS_LOADING", "java.net.URLClassLoader", 0.92,
                    "loadClass", "findClass"),
            exact("unsafe-define-class", "CLASS_LOADING", "sun.misc.Unsafe", 0.96,
                    "defineClass", "defineAnonymousClass"),
            exact("method-invoke", "REFLECTION", "java.lang.reflect.Method", 0.80, "invoke"),
            exact("constructor-new-instance", "REFLECTION", "java.lang.reflect.Constructor", 0.80, "newInstance"),

            exact("jdbc-statement", "SQL", "java.sql.Statement", 0.88,
                    "execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch"),
            exact("jdbc-connection-url", "SQL", "java.sql.DriverManager", 0.86, "getConnection"),
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
            descriptor("imageio-url", "SSRF", "javax.imageio.ImageIO", 0.86, "(Ljava/net/URL;",
                    Set.of("read")),
            exact("servlet-redirect", "REDIRECT", "javax.servlet.http.HttpServletResponse", 0.84,
                    "sendRedirect"),
            exact("jakarta-servlet-redirect", "REDIRECT", "jakarta.servlet.http.HttpServletResponse", 0.84,
                    "sendRedirect"),

            // JWT / token APIs — presence only; not proof of missing verification or exploitability.
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
                    "parse", "parseToken", "getToken", "createToken", "createAuthInfo"),
            prefix("blade-secure-token", "AUTH", "org.springblade.core.secure.", 0.78,
                    "getUser", "getUserId", "getClientId", "parseToken")
    );

    private JvmSinkSignatures() {
    }

    static Match match(BytecodeFactIndex.CallEdge edge) {
        if (edge == null || edge.kind() == BytecodeFactIndex.EdgeKind.UNRESOLVED) return null;
        // Executable Spring Boot archives carry launcher infrastructure outside
        // BOOT-INF/classes. Its class loading, archive I/O, and URL handlers are
        // implementation mechanics rather than application sinks and previously
        // dominated results for every Boot artifact.
        if (edge.callerOwner().startsWith("org.springframework.boot.loader.")) return null;
        for (Rule rule : RULES) {
            if (rule.matches(edge)) return new Match(rule.id, rule.category, rule.confidence);
        }
        return null;
    }

    record Match(String ruleId, String category, double confidence) {
    }

    private record Rule(String id, String category, String owner, boolean ownerPrefix,
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
        return descriptor(id, category, owner, confidence, null, Set.of(methods));
    }

    private static Rule prefix(String id, String category, String ownerPrefix, double confidence,
                               String... methods) {
        return new Rule(id, category, ownerPrefix, true, Set.of(methods), null, confidence);
    }

    private static Rule descriptor(String id, String category, String owner, double confidence,
                                   String descriptorPrefix, Set<String> methods) {
        return new Rule(id, category, owner, false, methods, descriptorPrefix, confidence);
    }
}
