package com.aq.jvmsentinel.instrumentation.mock;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

import java.lang.instrument.Instrumentation;
import java.util.Properties;

/**
 * 说明：Docker {@code --network none} 下 Quartz {@code AUTO} instance-id 生成常失败，
 * {@code Couldn't get host name} and surfaces as {@code Cannot run without an instance id}.
 * 启用 dependency mock 时，强制稳定 sandbox identity。
 */
public final class QuartzInstanceIdFailOpen {
    public static final String SANDBOX_INSTANCE_ID = "veyrion-sandbox";

    private QuartzInstanceIdFailOpen() {
    }

    public static void install(Instrumentation instrumentation) {
        new AgentBuilder.Default()
                .disableClassFormatChanges()
                .type(ElementMatchers.named("org.quartz.simpl.SimpleInstanceIdGenerator")
                        .or(ElementMatchers.named("org.quartz.simpl.HostnameInstanceIdGenerator")))
                .transform((builder, type, loader, module, domain) -> builder.visit(
                        Advice.to(GenerateInstanceIdAdvice.class)
                                .on(ElementMatchers.named("generateInstanceId")
                                        .and(ElementMatchers.takesArguments(0)))))
                .type(ElementMatchers.named("org.quartz.impl.StdSchedulerFactory"))
                .transform((builder, type, loader, module, domain) -> builder.visit(
                        Advice.to(StdSchedulerFactoryPropsAdvice.class)
                                .on(ElementMatchers.named("initialize")
                                        .and(ElementMatchers.takesArguments(1))
                                        .and(ElementMatchers.takesArgument(0, Properties.class)))))
                .installOn(instrumentation);
    }

    /** Public nested advice types so Byte Buddy can inline across class loaders. */
    public static final class GenerateInstanceIdAdvice {
        private GenerateInstanceIdAdvice() {
        }

        @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
        public static void exit(@Advice.Return(readOnly = false) String value,
                                @Advice.Thrown(readOnly = false) Throwable thrown) {
            if (thrown != null || value == null || value.isBlank()) {
                thrown = null;
                value = SANDBOX_INSTANCE_ID;
            }
        }
    }

    /**
     * 若应用以 {@code AUTO}/{@code SYS_PROP}/blank id 加载 Quartz properties，
     * 在 {@code StdSchedulerFactory} 实例化前 rewrite 为 literal sandbox id。
     */
    public static final class StdSchedulerFactoryPropsAdvice {
        private StdSchedulerFactoryPropsAdvice() {
        }

        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void enter(@Advice.Argument(0) Properties props) {
            if (props == null) {
                return;
            }
            String id = props.getProperty("org.quartz.scheduler.instanceId");
            if (id == null || id.isBlank()
                    || "AUTO".equalsIgnoreCase(id)
                    || "SYS_PROP".equalsIgnoreCase(id)) {
                props.setProperty("org.quartz.scheduler.instanceId", SANDBOX_INSTANCE_ID);
            }
            String name = props.getProperty("org.quartz.scheduler.instanceName");
            if (name == null || name.isBlank()) {
                props.setProperty("org.quartz.scheduler.instanceName", SANDBOX_INSTANCE_ID);
            }
            props.setProperty("org.quartz.jobStore.isClustered", "false");
        }
    }
}