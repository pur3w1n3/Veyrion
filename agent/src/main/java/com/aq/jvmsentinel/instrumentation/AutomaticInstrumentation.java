package com.aq.jvmsentinel.instrumentation;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.JavaModule;

import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Map;

import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isAnnotatedWith;
import static net.bytebuddy.matcher.ElementMatchers.isInterface;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.namedOneOf;
import static net.bytebuddy.matcher.ElementMatchers.not;

/**
 * Startup-only instrumentation. Bootstrap classes are deliberately not transformed; calls into selected JDK
 * APIs are observed at non-bootstrap application call sites instead.
 */
final class AutomaticInstrumentation {
    private static final String[] SPRING_MAPPING_ANNOTATIONS = {
            "org.springframework.web.bind.annotation.RequestMapping",
            "org.springframework.web.bind.annotation.GetMapping",
            "org.springframework.web.bind.annotation.PostMapping",
            "org.springframework.web.bind.annotation.PutMapping",
            "org.springframework.web.bind.annotation.DeleteMapping",
            "org.springframework.web.bind.annotation.PatchMapping"
    };

    private AutomaticInstrumentation() {
    }

    static void install(Instrumentation instrumentation, AgentConfig config, EventWriter writer) {
        AgentBuilder.RawMatcher applicationTypes = (type, loader, module, redefining, domain) ->
                loader != null && config.includes(type.getName());

        AgentBuilder.Listener listener = new AgentBuilder.Listener.Adapter() {
            @Override
            public void onError(String typeName, ClassLoader classLoader, JavaModule module,
                                boolean loaded, Throwable throwable) {
                writer.writeObserved("INSTRUMENTATION_ERROR", typeName, "",
                        Map.of("errorType", throwable.getClass().getName()));
            }
        };

        AgentBuilder builder = new AgentBuilder.Default()
                .with(listener)
                .disableClassFormatChanges()
                .type(applicationTypes)
                .transform(AutomaticInstrumentation::instrumentApplicationCalls);

        builder.installOn(instrumentation);
    }

    private static DynamicType.Builder<?> instrumentApplicationCalls(
            DynamicType.Builder<?> builder,
            TypeDescription type,
            ClassLoader loader,
            JavaModule module,
            ProtectionDomain domain) {
        DynamicType.Builder<?> instrumented = builder
                .visit(new DependencyCallSiteVisitor(type.getName()))
                .visit(Advice.to(SpringHandlerAdvice.class).on(
                        isMethod().and(isAnnotatedWith(namedOneOf(SPRING_MAPPING_ANNOTATIONS)))
                                .and(not(isAbstract()))));
        if (hasSuperType(named("java.sql.Statement")).matches(type) && !isInterface().matches(type)) {
            instrumented = instrumented.visit(Advice.to(JdbcAdvice.class).on(
                    isMethod().and(nameStartsWith("execute")).and(not(isAbstract()))));
        }
        if (hasSuperType(named("jakarta.servlet.Servlet")
                .or(named("javax.servlet.Servlet"))).matches(type)) {
            instrumented = instrumented.visit(Advice.to(ServletAdvice.class).on(
                    isMethod().and(namedOneOf("service", "doGet", "doPost", "doPut",
                            "doDelete", "doPatch", "doHead", "doOptions"))
                            .and(not(isAbstract()))));
        }
        return instrumented;
    }

    public static final class JdbcAdvice {
        private JdbcAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName) {
            AgentRuntime.recordTransformedMethod(
                    "JDBC", className, methodName, "IMPLEMENTATION_METHOD");
        }
    }

    public static final class ServletAdvice {
        private ServletAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName) {
            AgentRuntime.recordTransformedMethod(
                    "HTTP", className, methodName, "SERVLET_METHOD");
        }
    }

    public static final class SpringHandlerAdvice {
        private SpringHandlerAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Origin("#t") String className,
                                 @Advice.Origin("#m") String methodName) {
            AgentRuntime.recordTransformedMethod(
                    "HTTP", className, methodName, "SPRING_MAPPING_ANNOTATION");
        }
    }

    private static final class DependencyCallSiteVisitor extends AsmVisitorWrapper.AbstractBase {
        private final String callerClass;

        private DependencyCallSiteVisitor(String callerClass) {
            this.callerClass = callerClass;
        }

        @Override
        public ClassVisitor wrap(TypeDescription instrumentedType, ClassVisitor classVisitor,
                                 Implementation.Context implementationContext, TypePool typePool,
                                 FieldList<FieldDescription.InDefinedShape> fields,
                                 MethodList<?> methods, int writerFlags, int readerFlags) {
            return new ClassVisitor(Opcodes.ASM9, classVisitor) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
                    return new MethodVisitor(Opcodes.ASM9, delegate) {
                        private int invocationOrdinal;

                        @Override
                        public void visitMethodInsn(int opcode, String owner, String methodName,
                                                    String methodDescriptor, boolean isInterface) {
                            String eventType = eventType(owner, methodName);
                            if (eventType != null) {
                                super.visitLdcInsn(eventType);
                                super.visitLdcInsn(callerClass);
                                super.visitLdcInsn(name + descriptor);
                                super.visitLdcInsn(owner.replace('/', '.'));
                                super.visitLdcInsn(methodName);
                                super.visitLdcInsn(Integer.toString(invocationOrdinal));
                                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                        "com/aq/jvmsentinel/instrumentation/AgentRuntime",
                                        "recordInstrumentedCall",
                                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                                                + "Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                                        false);
                            }
                            invocationOrdinal++;
                            super.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface);
                        }

                        @Override
                        public void visitMaxs(int maxStack, int maxLocals) {
                            super.visitMaxs(maxStack + 6, maxLocals);
                        }
                    };
                }
            };
        }

        private static String eventType(String owner, String methodName) {
            if ("java/net/http/HttpClient".equals(owner)
                    && ("send".equals(methodName) || "sendAsync".equals(methodName))) {
                return "HTTP_CLIENT";
            }
            if ("java/lang/ProcessBuilder".equals(owner) && "start".equals(methodName)
                    || "java/lang/Runtime".equals(owner) && methodName.startsWith("exec")) {
                return "PROCESS";
            }
            if ("java/nio/file/Files".equals(owner)
                    && (methodName.startsWith("write") || "newOutputStream".equals(methodName))) {
                return "FILE";
            }
            if (("java/io/FileOutputStream".equals(owner) || "java/io/FileWriter".equals(owner))
                    && "<init>".equals(methodName)) {
                return "FILE";
            }
            return null;
        }
    }
}
