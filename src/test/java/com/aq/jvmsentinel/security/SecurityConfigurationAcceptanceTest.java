package com.aq.jvmsentinel.security;

import com.aq.jvmsentinel.ai.AiContracts;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.ProviderContracts;
import com.aq.jvmsentinel.security.ProviderSecretCipher.EncryptedSecret;
import com.aq.jvmsentinel.security.ProviderSecretCipher.SecretIntegrityException;
import com.aq.jvmsentinel.security.ProviderSecretCipher.SecretScope;
import com.aq.jvmsentinel.security.auth.AuthContext;
import com.aq.jvmsentinel.security.auth.Authorizer;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.aq.jvmsentinel.security.auth.Permission;
import com.aq.jvmsentinel.security.auth.WorkerCredential;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Pure-JDK acceptance checks for the standalone security configuration domain. */
public final class SecurityConfigurationAcceptanceTest {
    public static void main(String[] args) throws Exception {
        cipherBindsEveryScopeDimension();
        rootKeyIsFileBackedAndStable();
        publicDtosNeverEchoSecrets();
        rbacMatrixIsDefaultDeny();
        workerCredentialCannotBecomeOperator();
        aiConclusionsRemainInference();
        System.out.println("SecurityConfigurationAcceptanceTest: PASS");
    }

    private static void cipherBindsEveryScopeDimension() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey key = generator.generateKey();
        ProviderSecretCipher cipher = new ProviderSecretCipher();
        SecretScope scope = new SecretScope("workspace-a", "provider-a", "credential-a", 7);
        byte[] plaintext = "provider-secret-value".getBytes(StandardCharsets.UTF_8);
        EncryptedSecret encrypted = cipher.encrypt(key, scope, plaintext);
        check(Arrays.equals(plaintext, cipher.decrypt(key, scope, encrypted)), "cipher round trip");

        byte[] tamperedCiphertext = encrypted.ciphertext();
        tamperedCiphertext[tamperedCiphertext.length - 1] ^= 1;
        expectIntegrity(() -> cipher.decrypt(key, scope, new EncryptedSecret(
                encrypted.formatVersion(), encrypted.credentialVersion(),
                encrypted.nonce(), tamperedCiphertext)), "ciphertext tamper");

        byte[] tamperedNonce = encrypted.nonce();
        tamperedNonce[0] ^= 1;
        expectIntegrity(() -> cipher.decrypt(key, scope, new EncryptedSecret(
                encrypted.formatVersion(), encrypted.credentialVersion(),
                tamperedNonce, encrypted.ciphertext())), "nonce tamper");

        List<SecretScope> wrongScopes = List.of(
                new SecretScope("workspace-b", "provider-a", "credential-a", 7),
                new SecretScope("workspace-a", "provider-b", "credential-a", 7),
                new SecretScope("workspace-a", "provider-a", "credential-b", 7),
                new SecretScope("workspace-a", "provider-a", "credential-a", 8));
        for (SecretScope wrong : wrongScopes) {
            EncryptedSecret value = wrong.credentialVersion() == encrypted.credentialVersion()
                    ? encrypted : new EncryptedSecret(encrypted.formatVersion(), wrong.credentialVersion(),
                    encrypted.nonce(), encrypted.ciphertext());
            expectIntegrity(() -> cipher.decrypt(key, wrong, value), "AAD scope tamper: " + wrong);
        }
        expectIntegrity(() -> cipher.decrypt(key, scope, new EncryptedSecret(
                2, encrypted.credentialVersion(), encrypted.nonce(), encrypted.ciphertext())),
                "format tamper");
        check(!encrypted.toString().contains("ciphertext"), "encrypted value toString is redacted");
    }

    private static void rootKeyIsFileBackedAndStable() throws Exception {
        Path directory = Files.createTempDirectory("veyrion-root-key");
        Path keyFile = directory.resolve("security").resolve("root.key");
        RootKeyStore store = new RootKeyStore(keyFile);
        RootKeyStore.DeploymentPolicy local =
                new RootKeyStore.DeploymentPolicy(true, false);
        RootKeyStore.LoadedRootKey first = store.loadOrCreate(local);
        RootKeyStore.LoadedRootKey second = store.loadOrCreate(local);
        check(first.created(), "first root key load creates key");
        check(!second.created(), "second root key load reuses key");
        check(Files.size(keyFile) == 32, "root key is exactly 256 bits");
        check(Arrays.equals(first.key().getEncoded(), second.key().getEncoded()), "root key is stable");
        check(new RootKeyStore.DeploymentPolicy(false, false).requiresConfirmedPermissions(),
                "non-loopback requires confirmed permissions");
        check(new RootKeyStore.DeploymentPolicy(true, true).requiresConfirmedPermissions(),
                "production requires confirmed permissions");
        check(!local.requiresConfirmedPermissions(), "local loopback tolerates unconfirmed permissions");
    }

    private static void publicDtosNeverEchoSecrets() {
        Instant now = Instant.parse("2026-07-24T00:00:00Z");
        ProviderContracts.ProviderDefinition provider = new ProviderContracts.ProviderDefinition(
                1, "workspace-a", "provider-a", "Provider A",
                ProviderContracts.ProviderKind.OPENAI_COMPATIBLE,
                URI.create("https://provider.invalid/v1"), true, true, now, now);
        ProviderContracts.ModelDefinition model = new ProviderContracts.ModelDefinition(
                1, "workspace-a", "model-a", "provider-a", "model-name",
                32_768, true, now, now);
        ProviderContracts.AgentRoleBinding binding = new ProviderContracts.AgentRoleBinding(
                1, "workspace-a", AgentRole.PRE_ANALYSIS, "model-a", true, now);
        String response = provider + "\n" + model + "\n" + binding;
        check(!response.contains("provider-secret-value"), "public DTO has zero secret echo");
        for (var component : ProviderContracts.ProviderDefinition.class.getRecordComponents()) {
            String name = component.getName().toLowerCase(java.util.Locale.ROOT);
            check(!name.contains("secret") && !name.contains("ciphertext") && !name.contains("token"),
                    "provider response field cannot contain credential material");
        }
        check(EnumSet.allOf(AgentRole.class).equals(EnumSet.of(
                AgentRole.PRE_ANALYSIS, AgentRole.PATH_EXPLORATION,
                AgentRole.DYNAMIC_VERIFICATION, AgentRole.VULNERABILITY_TRIAGE,
                AgentRole.REPORT_GENERATION)),
                "agent roles are the fixed five-role set");
    }

    private static void rbacMatrixIsDefaultDeny() {
        Authorizer authorizer = new Authorizer();
        Map<OperatorRole, Set<Permission>> expected = Map.of(
                OperatorRole.VIEWER, Set.of(Permission.READ_SECURITY_CONFIGURATION),
                OperatorRole.ANALYST, Set.of(
                        Permission.READ_SECURITY_CONFIGURATION, Permission.RUN_AI_JOBS,
                        Permission.RUN_SCANS, Permission.READ_AUDIT),
                OperatorRole.OPERATOR, Set.of(
                        Permission.READ_SECURITY_CONFIGURATION, Permission.MANAGE_PROVIDERS,
                        Permission.MANAGE_MODELS, Permission.ASSIGN_AGENT_ROLES,
                        Permission.ROTATE_PROVIDER_SECRETS, Permission.RUN_AI_JOBS,
                        Permission.MANAGE_PROJECTS, Permission.RUN_SCANS, Permission.READ_AUDIT),
                OperatorRole.ADMINISTRATOR, EnumSet.allOf(Permission.class));
        for (OperatorRole role : OperatorRole.values()) {
            AuthContext context = AuthContext.authenticated("operator-a", "workspace-a", Set.of(role));
            for (Permission permission : Permission.values()) {
                boolean actual = authorizer.authorize(context, "workspace-a", permission).allowed();
                check(actual == expected.get(role).contains(permission),
                        "RBAC matrix mismatch for " + role + "/" + permission);
            }
        }
        AuthContext admin = AuthContext.authenticated(
                "admin-a", "workspace-a", Set.of(OperatorRole.ADMINISTRATOR));
        check(!authorizer.authorize(admin, "workspace-b", Permission.MANAGE_PROVIDERS).allowed(),
                "cross-workspace admin is denied");
        check(!authorizer.authorize(AuthContext.unauthenticated("workspace-a"),
                "workspace-a", Permission.READ_SECURITY_CONFIGURATION).allowed(),
                "unauthenticated context is denied");
        check(!new Authorizer(Map.of()).authorize(admin,
                "workspace-a", Permission.READ_SECURITY_CONFIGURATION).allowed(),
                "missing role mapping defaults to deny");
    }

    private static void workerCredentialCannotBecomeOperator() {
        byte[] token = "worker-token-material-that-is-at-least-32-bytes".getBytes(StandardCharsets.UTF_8);
        try (WorkerCredential worker = new WorkerCredential("worker-a", token)) {
            Authorizer.Decision decision = new Authorizer().authorizeCredential(
                    worker, "workspace-a", Permission.MANAGE_PROVIDERS);
            check(!decision.allowed() && "WRONG_PRINCIPAL_TYPE".equals(decision.denialCode()),
                    "worker token confusion is denied");
            check(worker.matches(token), "worker credential still authenticates only as worker");
            check(!worker.toString().contains(new String(token, StandardCharsets.UTF_8)),
                    "worker token is redacted");
        }
    }

    private static void aiConclusionsRemainInference() {
        Instant now = Instant.parse("2026-07-24T00:00:00Z");
        AiContracts.InferenceConclusion conclusion =
                new AiContracts.InferenceConclusion("Possible unsafe flow", 0.75, List.of("evidence-a"));
        AiContracts.AiStage stage = new AiContracts.AiStage(
                1, "workspace-a", "job-a", "stage-a", AgentRole.VULNERABILITY_TRIAGE,
                "model-a", AiContracts.StageStatus.COMPLETED, List.of("fact-a"),
                conclusion, now, now);
        AiContracts.AiJob job = new AiContracts.AiJob(
                1, "workspace-a", "job-a", "a".repeat(64), AiContracts.JobStatus.COMPLETED,
                List.of(stage), now, now);
        check(job.stages().get(0).conclusion().classification()
                        == AiContracts.ConclusionKind.INFERENCE,
                "AI conclusion is fixed to INFERENCE");
        check(Arrays.equals(AiContracts.ConclusionKind.values(),
                new AiContracts.ConclusionKind[]{AiContracts.ConclusionKind.INFERENCE}),
                "AI conclusion type has no VERIFIED state");
    }

    private static void expectIntegrity(Runnable action, String message) {
        try {
            action.run();
            throw new AssertionError(message + " was accepted");
        } catch (SecretIntegrityException expected) {
            // fail-closed
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
