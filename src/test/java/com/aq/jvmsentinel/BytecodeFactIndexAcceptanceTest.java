package com.aq.jvmsentinel;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Executable acceptance checks for bounded, load-free bytecode fact indexing. */
public final class BytecodeFactIndexAcceptanceTest {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("bytecode-fact-index-test");
        Path sources = Files.createDirectories(root.resolve("sources"));
        Path classes = Files.createDirectories(root.resolve("classes"));
        writeFixtures(sources);
        compile(sources, classes);
        Path jar = root.resolve("facts.jar");
        archive(classes, jar);

        PreAnalysisResult result = new PreAnalysisService().analyze(
                ArtifactMetadataReader.read(new ArtifactRegistry(root).register(jar)));
        BytecodeFactIndex index = result.bytecodeFactIndex();

        BytecodeFactIndex.ClassFact child = index.classes().stream()
                .filter(fact -> fact.className().equals("fixture.Child")).findFirst().orElseThrow();
        check(child.superClassName().equals("fixture.Base"), "superclass fact");
        check(index.classes().stream().filter(fact -> fact.className().equals("fixture.Base"))
                .flatMap(fact -> fact.interfaces().stream()).anyMatch("fixture.Worker"::equals), "interface fact");
        check(index.fields().stream().anyMatch(fact -> fact.owner().equals("fixture.Base")
                && fact.name().equals("value") && fact.descriptor().equals("I")), "field declaration fact");
        check(index.methods().stream().anyMatch(fact -> fact.owner().equals("fixture.Child")
                && fact.name().equals("exercise")), "method declaration fact");

        Set<BytecodeFactIndex.AccessKind> accessKinds = index.memberAccesses().stream()
                .map(BytecodeFactIndex.MemberAccessFact::kind).collect(Collectors.toSet());
        check(accessKinds.containsAll(Set.of(
                BytecodeFactIndex.AccessKind.FIELD_READ,
                BytecodeFactIndex.AccessKind.FIELD_WRITE,
                BytecodeFactIndex.AccessKind.INVOKE_VIRTUAL,
                BytecodeFactIndex.AccessKind.INVOKE_SPECIAL,
                BytecodeFactIndex.AccessKind.INVOKE_STATIC,
                BytecodeFactIndex.AccessKind.INVOKE_INTERFACE,
                BytecodeFactIndex.AccessKind.INVOKE_DYNAMIC)), "all member access opcodes");

        check(index.callEdges().stream().anyMatch(edge -> edge.kind() == BytecodeFactIndex.EdgeKind.DIRECT
                && edge.targetName().equals("helper")), "static direct edge");
        check(index.callEdges().stream().anyMatch(edge -> edge.kind() == BytecodeFactIndex.EdgeKind.CONSERVATIVE_CHA
                && edge.targetOwner().equals("fixture.Worker")), "interface conservative CHA edge");
        check(index.callEdges().stream().anyMatch(edge -> edge.kind() == BytecodeFactIndex.EdgeKind.UNRESOLVED
                && edge.targetOwner().equals("<dynamic>")), "invokedynamic unresolved edge");
        check(index.unresolvedDynamics().stream().map(BytecodeFactIndex.UnresolvedDynamicFact::mechanism)
                .collect(Collectors.toSet()).containsAll(Set.of(
                        "INVOKEDYNAMIC", "REFLECTION", "DYNAMIC_PROXY", "JNI")), "dynamic mechanisms unresolved");

        List<String> evidenceKeys = index.memberAccesses().stream()
                .map(fact -> fact.evidence().stableKey()).toList();
        check(evidenceKeys.size() == evidenceKeys.stream().distinct().count(),
                "instruction evidence keys are stable and unique");
        check(index.memberAccesses().stream().allMatch(fact ->
                fact.evidence().className() != null
                        && fact.evidence().methodName() != null
                        && fact.evidence().bytecodeOffset() >= 0
                        && fact.evidence().ordinal() >= 0), "instruction evidence location");

        check(index.methods().stream().anyMatch(fact -> fact.name().equals("switchValue")),
                "tableswitch/lookupswitch method remains parseable");
        System.out.println("BytecodeFactIndexAcceptanceTest: PASS");
    }

    private static void writeFixtures(Path root) throws Exception {
        source(root, "fixture/Worker.java",
                "package fixture; public interface Worker { String work(); }\n");
        source(root, "fixture/Base.java", """
                package fixture;
                public class Base implements Worker {
                    protected int value;
                    protected static int global;
                    public String work() { return "base"; }
                }
                """);
        source(root, "fixture/Child.java", """
                package fixture;
                import java.lang.reflect.Method;
                import java.lang.reflect.Proxy;
                public class Child extends Base {
                    public native void nativeCall();
                    public String work() { return "child"; }
                    private static String helper() { return "helper"; }
                    public Object exercise(Worker worker, Method reflected) throws Exception {
                        value = global;
                        global = value;
                        String a = helper();
                        String b = work();
                        String c = worker.work();
                        Runnable lambda = () -> helper();
                        lambda.run();
                        Object dynamic = reflected.invoke(this);
                        Object proxy = Proxy.newProxyInstance(
                                getClass().getClassLoader(), new Class<?>[]{Worker.class}, (p,m,args) -> "proxy");
                        return a + b + c + dynamic + proxy;
                    }
                    public int switchValue(int input) {
                        return switch (input) { case -1 -> 1; case 2 -> 2; case 100 -> 3; default -> 0; };
                    }
                }
                """);
    }

    private static void source(Path root, String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    private static void compile(Path sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        check(compiler != null, "tests require a JDK compiler");
        List<Path> files;
        try (Stream<Path> stream = Files.walk(sources)) {
            files = stream.filter(path -> path.toString().endsWith(".java")).toList();
        }
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean success = compiler.getTask(null, manager, null,
                    List.of("--release", "17", "-d", classes.toString()), null,
                    manager.getJavaFileObjectsFromPaths(files)).call();
            check(success, "fixture compilation");
        }
    }

    private static void archive(Path classes, Path jar) throws Exception {
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar));
             Stream<Path> stream = Files.walk(classes)) {
            for (Path file : stream.filter(Files::isRegularFile).toList()) {
                output.putNextEntry(new ZipEntry(classes.relativize(file).toString().replace('\\', '/')));
                Files.copy(file, output);
                output.closeEntry();
            }
        }
    }

    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }
}
