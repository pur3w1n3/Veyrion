package com.aq.jvmsentinel.cli;

import com.aq.jvmsentinel.analysis.ArtifactMetadataReader;
import com.aq.jvmsentinel.analysis.PreAnalysisInput;
import com.aq.jvmsentinel.analysis.PreAnalysisResult;
import com.aq.jvmsentinel.analysis.PreAnalysisService;
import com.aq.jvmsentinel.artifact.ArtifactRegistry;
import com.aq.jvmsentinel.event.*;
import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.policy.*;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.util.List;

/** Local metadata-only entry point. It never starts or executes an imported artifact. */
public final class Main {
    private Main() { }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args.length > 2 || (args.length == 2 && !args[1].equals("--authorize"))) {
            System.err.println("usage: java ... com.aq.jvmsentinel.cli.Main <artifact.jar|war|class> [--authorize]");
            System.exit(2);
            return;
        }
        Path artifactPath = Paths.get(args[0]).toAbsolutePath().normalize();
        ScanPolicy policy = new ScanPolicy(args.length == 2, NetworkMode.DENY, DangerousActionMode.DRY_RUN,
                List.of(), 900, 4L * 1024 * 1024 * 1024, 2L * 1024 * 1024 * 1024);
        try {
            PolicyValidator.requireStartAllowed(policy);
        } catch (PolicyViolationException violation) {
            System.err.println("REJECTED: " + violation.getMessage());
            System.exit(3);
            return;
        }
        Path allowedRoot = artifactPath.getParent();
        if (allowedRoot == null) {
            System.err.println("REJECTED: artifact must have a parent directory");
            System.exit(3);
            return;
        }
        ArtifactRegistry registry = new ArtifactRegistry(allowedRoot);
        ArtifactDescriptor descriptor = registry.register(artifactPath);
        registry.verifyUnchanged(descriptor);
        PreAnalysisResult result = new PreAnalysisService().analyze(readMetadata(descriptor));
        String scanId = "scan-" + descriptor.artifactId();
        VersionedEvent event = EventFactory.create("PreAnalysisCompleted", 1,
                new EventContext("local-demo", descriptor.sha256(), scanId, "task-preanalysis"),
                new IdempotencyKey("artifact", descriptor.sha256()), "{\"status\":\"completed\"}", Clock.systemUTC());
        System.out.println(JsonRenderer.render(descriptor, policy, result, event));
    }

    /** Safe, metadata-only reader shared by the local CLI and Control Plane. */
    public static PreAnalysisInput readMetadata(ArtifactDescriptor descriptor) throws IOException {
        return ArtifactMetadataReader.read(descriptor);
    }
}
