package com.aq.jvmsentinel.control.http;

import com.aq.jvmsentinel.model.ArtifactDescriptor;
import com.aq.jvmsentinel.artifact.ArtifactUploadService;
import com.aq.jvmsentinel.artifact.ArtifactValidationException;
import com.aq.jvmsentinel.control.ApiDtos;
import com.aq.jvmsentinel.control.ControlPlaneStore;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence;
import com.aq.jvmsentinel.model.ArtifactType;
import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.provider.ProviderContracts.ModelInventory;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.security.ProviderSecretCipher;
import com.aq.jvmsentinel.verification.VerifiedStatusGate;
import com.aq.jvmsentinel.control.WorkerControlPlaneApi;
import com.aq.jvmsentinel.security.auth.AuthContext;
import com.aq.jvmsentinel.security.auth.Authorizer;
import com.aq.jvmsentinel.security.auth.OperatorRole;
import com.aq.jvmsentinel.security.auth.Permission;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** 从 ControlPlaneRouteHandlers 拆出的 HTTP 处理器：OperatorProvider 域。 */
final class OperatorProviderHttpHandlers extends ControlPlaneHandlerSupport {

    OperatorProviderHttpHandlers(ControlPlaneHandlerHost host) {
        super(host);
    }

    public synchronized void createProject(HttpExchange exchange) throws IOException {
        String idempotencyHeader = ControlPlaneHttpSupport.requestIdempotencyKey(exchange);
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String payload = JsonCodec.stringify(body);
        String durableScope = "project:create";
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency,
                idempotencyHeader == null ? null : ControlPlaneHttpSupport.idempotencyMapKey(durableScope, idempotencyHeader));
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, idempotencyHeader, payload);
        if (idempotencyHeader != null) {
            String existingId = host.idempotentProjects.get(idempotencyHeader);
            if (existingId == null && durable != null) existingId = durable.resultRef();
            if (existingId != null) {
                sendProject(exchange, existingId);
                return;
            }
        }
        String id = ControlPlaneHttpSupport.optionalText(body, "projectId", ControlPlaneHttpSupport.optionalText(body, "id", null));
        String name = ControlPlaneHttpSupport.optionalText(body, "name", ControlPlaneHttpSupport.optionalText(body, "displayName", null));
        ControlPlaneStore.ProjectRecord project = host.store.createProject(id, name, Instant.now(host.clock).toString(),
                actor(exchange).operatorId());
        if (idempotencyHeader != null) {
            host.idempotentProjects.put(idempotencyHeader, project.projectId());
            rememberDurableIdempotency(durableScope, idempotencyHeader, payload, project.projectId(), null);
        }
        ControlPlaneHttpSupport.sendJson(exchange, 201, projectMap(project));
    }
    public void sendProject(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneHttpSupport.sendJson(exchange, 200, projectMap(host.store.requireProject(projectId)));
    }
    public void listProjects(HttpExchange exchange) throws IOException {
        List<Object> projects = new ArrayList<>();
        for (ControlPlaneStore.ProjectRecord project : host.store.projects()) projects.add(projectMap(project));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("projects", projects);
        result.put("items", projects);
        ControlPlaneHttpSupport.sendJson(exchange, 200, result);
    }
    public synchronized void updateProject(HttpExchange exchange, String projectId) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        for (String field : body.keySet()) {
            if (!Set.of("name", "status").contains(field)) {
                throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_FIELD", "project patch only accepts name and status");
            }
        }
        if (body.isEmpty()) throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_FIELD", "project patch cannot be empty");
        String name = body.containsKey("name") ? ControlPlaneHttpSupport.optionalText(body, "name", null) : null;
        String status = body.containsKey("status") ? ControlPlaneHttpSupport.optionalText(body, "status", null) : null;
        ControlPlaneHttpSupport.sendJson(exchange, 200, projectMap(host.store.updateProject(projectId, name, status,
                Instant.now(host.clock).toString(), actor(exchange).operatorId())));
    }
    public synchronized void deleteProject(HttpExchange exchange, String projectId) throws IOException {
        host.store.softDeleteProject(projectId, Instant.now(host.clock).toString(), actor(exchange).operatorId());
        ControlPlaneHttpSupport.sendEmpty(exchange, 204);
    }
    public void listOperators(HttpExchange exchange) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var operator : host.store.operators()) items.add(operatorMap(operator, null));
        ControlPlaneHttpSupport.sendJson(exchange, 200, stringEnvelope("operators", items));
    }
    public void createOperator(HttpExchange exchange) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String username = ControlPlaneHttpSupport.optionalText(body, "username", null);
        OperatorRole role = operatorRole(ControlPlaneHttpSupport.optionalText(body, "role", null));
        String now = Instant.now(host.clock).toString();
        ControlPlaneStore.CreatedOperator created =
                host.store.createOperator(username, role, actor(exchange).operatorId(), now);
        ControlPlaneHttpSupport.sendJson(exchange, 201, operatorMap(created.operator(), created.personalAccessToken()));
    }
    public void updateOperator(HttpExchange exchange, String operatorId) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        OperatorRole role = operatorRole(ControlPlaneHttpSupport.optionalText(body, "role", null));
        boolean revoke = ControlPlaneHttpSupport.optionalBoolean(body, "revokeTokens", false);
        AuthContext actor = actor(exchange);
        if (actor.operatorId().equals(operatorId)
                && (revoke || role != OperatorRole.ADMINISTRATOR)) {
            throw new ControlPlaneHttpSupport.ApiException(409, "SELF_LOCKOUT_REJECTED",
                    "administrator cannot revoke or demote the active account");
        }
        host.store.updateOperator(operatorId, role, revoke, actor.operatorId(), Instant.now(host.clock).toString());
        var updated = host.store.operators().stream().filter(value -> value.operatorId().equals(operatorId))
                .findFirst().orElseThrow(() -> new ControlPlaneStore.MissingRecordException("operator not found"));
        ControlPlaneHttpSupport.sendJson(exchange, 200, operatorMap(updated, null));
    }
    public void listProviders(HttpExchange exchange) throws IOException {
        List<Object> items = new ArrayList<>(host.providerQueryPort.listProviders());
        ControlPlaneHttpSupport.sendJson(exchange, 200, stringEnvelope("providers", items));
    }
    public void createProvider(HttpExchange exchange) throws IOException {
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String id = ControlPlaneHttpSupport.optionalText(body, "providerId",
                "provider-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16));
        var saved = saveProviderBody(exchange, id, body, null);
        ControlPlaneHttpSupport.sendJson(exchange, 201, providerMap(saved));
    }
    public void updateProvider(HttpExchange exchange, String providerId) throws IOException {
        var existing = host.store.requireProvider(providerId);
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        ControlPlaneHttpSupport.sendJson(exchange, 200, providerMap(saveProviderBody(exchange, providerId, body, existing)));
    }
    public void deleteProvider(HttpExchange exchange, String providerId) throws IOException {
        host.store.deleteProvider(providerId, actor(exchange).operatorId(), Instant.now(host.clock).toString());
        ControlPlaneHttpSupport.sendEmpty(exchange, 204);
    }
    public void refreshProviderModels(HttpExchange exchange, String providerId) throws IOException {
        var provider = host.store.requireProvider(providerId);
        if (!provider.enabled()) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PROVIDER_DISABLED",
                    "provider must be enabled before inventory refresh");
        }
        if (!provider.hasCredential()) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PROVIDER_CREDENTIAL_REQUIRED",
                    "provider credential is required for inventory refresh");
        }
        if (provider.kind() == ProviderKind.AZURE_OPENAI) {
            throw new ControlPlaneHttpSupport.ApiException(422, "PROVIDER_INVENTORY_UNSUPPORTED",
                    "provider kind does not support model inventory");
        }
        ProviderDefinition definition;
        try {
            definition = new ProviderDefinition(1,
                    com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                    provider.providerId(), provider.name(), provider.kind(), URI.create(provider.baseUrl()),
                    provider.enabled(), provider.hasCredential(), Instant.parse(provider.createdAt()),
                    Instant.parse(provider.updatedAt()));
        } catch (RuntimeException invalidConfiguration) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PROVIDER_CONFIGURATION_INVALID",
                    "provider configuration is invalid");
        }
        ModelInventory inventory;
        try {
            inventory = host.store.withProviderCredential(providerId,
                    credential -> host.providerInventoryService.fetch(definition, credential));
        } catch (ProviderSecretCipher.SecretCipherException invalidCredential) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PROVIDER_CREDENTIAL_INVALID",
                    "provider credential could not be used");
        } catch (ControlPlaneStore.MissingRecordException missingCredential) {
            throw new ControlPlaneHttpSupport.ApiException(409, "PROVIDER_CREDENTIAL_REQUIRED",
                    "provider credential is required for inventory refresh");
        } catch (RuntimeException providerFailure) {
            throw new ControlPlaneHttpSupport.ApiException(502, "PROVIDER_INVENTORY_FAILED",
                    "provider inventory request failed");
        }
        if (inventory == null
                || !definition.workspaceId().equals(inventory.workspaceId())
                || !providerId.equals(inventory.providerId())) {
            throw new ControlPlaneHttpSupport.ApiException(502, "PROVIDER_INVENTORY_INVALID",
                    "provider inventory response was invalid");
        }
        ControlPlaneHttpSupport.sendJson(exchange, 200, inventoryMap(inventory));
    }
    com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.ProviderData saveProviderBody(
            HttpExchange exchange, String providerId, Map<String, Object> body,
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.ProviderData existing) {
        String name = ControlPlaneHttpSupport.optionalText(body, "name", existing == null ? null : existing.name());
        String kindText = ControlPlaneHttpSupport.optionalText(body, "kind", existing == null ? null : existing.kind().name());
        String baseUrl = ControlPlaneHttpSupport.optionalText(body, "baseUrl", existing == null ? null : existing.baseUrl());
        if (name == null || kindText == null || baseUrl == null) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_PROVIDER", "name, kind, and baseUrl are required");
        }
        ProviderKind kind;
        try { kind = ProviderKind.valueOf(kindText); }
        catch (IllegalArgumentException invalid) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_PROVIDER_KIND", "unsupported provider kind");
        }
        String model = ControlPlaneHttpSupport.optionalText(body, "model", existing == null ? null : existing.model());
        boolean enabled = ControlPlaneHttpSupport.optionalBoolean(body, "enabled", existing == null || existing.enabled());
        String apiKey = body.containsKey("apiKey") ? ControlPlaneHttpSupport.optionalText(body, "apiKey", null) : null;
        return host.store.saveProvider(providerId, name, kind, baseUrl, model, enabled, apiKey,
                actor(exchange).operatorId(), Instant.now(host.clock).toString());
    }
    public synchronized void registerArtifact(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(projectId);
        String idempotencyHeader = ControlPlaneHttpSupport.requestIdempotencyKey(exchange);
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.idempotentArtifacts,
                idempotencyHeader == null ? null : projectId + ":" + idempotencyHeader);
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String payload = JsonCodec.stringify(body);
        String durableScope = "artifact:create:" + projectId;
        ControlPlaneHttpSupport.ensureIdempotencyCapacity(host.durableIdempotency,
                idempotencyHeader == null ? null : ControlPlaneHttpSupport.idempotencyMapKey(durableScope, idempotencyHeader));
        if (body.containsKey("authorized") && !ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED", "artifact authorization was denied");
        }
        SQLiteControlPlanePersistence.IdempotencyData durable = existingDurableIdempotency(
                durableScope, idempotencyHeader, payload);
        if (idempotencyHeader != null) {
            String existingDigest = host.idempotentArtifacts.get(projectId + ":" + idempotencyHeader);
            if (existingDigest == null && durable != null) existingDigest = durable.resultRef();
            if (existingDigest != null) {
                ArtifactDescriptor existing = host.store.artifact(project, existingDigest);
                if (existing != null) {
                    ControlPlaneHttpSupport.sendJson(exchange, 200, artifactMap(artifactDto(projectId, existing)));
                    return;
                }
            }
        }
        String rawPath = ControlPlaneHttpSupport.optionalText(body, "path", ControlPlaneHttpSupport.optionalText(body, "artifactPath", null));
        if (rawPath == null) throw new ControlPlaneHttpSupport.ApiException(400, "PATH_REQUIRED", "artifact path is required");
        ArtifactDescriptor descriptor = host.artifactRegistry.register(Path.of(rawPath));
        host.artifactRegistry.verifyUnchanged(descriptor);
        host.store.registerArtifact(project, descriptor, actor(exchange).operatorId());
        if (idempotencyHeader != null) {
            host.idempotentArtifacts.putIfAbsent(projectId + ":" + idempotencyHeader, descriptor.sha256());
            rememberDurableIdempotency(durableScope, idempotencyHeader, payload, descriptor.sha256(), null);
        }
        ControlPlaneHttpSupport.sendJson(exchange, 201, artifactMap(artifactDto(projectId, descriptor)));
    }
    public void initializeArtifactUpload(HttpExchange exchange, String projectId) throws IOException {
        host.store.requireProject(projectId);
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        String fileName = ControlPlaneHttpSupport.optionalText(body, "fileName", null);
        String sha256 = ControlPlaneHttpSupport.optionalText(body, "sha256", null);
        if (fileName == null || sha256 == null || !body.containsKey("sizeBytes")) {
            throw new ControlPlaneHttpSupport.ApiException(400, "UPLOAD_METADATA_REQUIRED",
                    "fileName, sizeBytes and sha256 are required");
        }
        long sizeBytes = ControlPlaneHttpSupport.positiveLong(body, "sizeBytes", -1);
        ArtifactUploadService.UploadSession session =
                host.artifactUploadService.initialize(projectId, fileName, sizeBytes, sha256);
        ControlPlaneHttpSupport.sendJson(exchange, 201, uploadSessionMap(session));
    }
    public void appendArtifactUpload(HttpExchange exchange, String projectId,
                                      String uploadId) throws IOException {
        host.store.requireProject(projectId);
        String rawOffset = ControlPlaneHttpSupport.query(exchange.getRequestURI(), "offset");
        if (rawOffset == null) {
            throw new ControlPlaneHttpSupport.ApiException(400, "OFFSET_REQUIRED", "offset query parameter is required");
        }
        long offset = ControlPlaneHttpSupport.nonNegativeLong(rawOffset, "offset");
        String rawLength = exchange.getRequestHeaders().getFirst("Content-Length");
        if (rawLength == null) {
            throw new ControlPlaneHttpSupport.ApiException(411, "CONTENT_LENGTH_REQUIRED", "Content-Length is required");
        }
        long contentLength = ControlPlaneHttpSupport.parseContentLength(rawLength);
        String chunkSha256 = exchange.getRequestHeaders().getFirst("X-Chunk-SHA256");
        if (chunkSha256 == null) {
            throw new ControlPlaneHttpSupport.ApiException(400, "CHUNK_DIGEST_REQUIRED", "X-Chunk-SHA256 is required");
        }
        ArtifactUploadService.UploadSession session = host.artifactUploadService.append(
                projectId, uploadId, offset, contentLength, chunkSha256, exchange.getRequestBody());
        ControlPlaneHttpSupport.sendJson(exchange, 200, uploadSessionMap(session));
    }
    public void completeArtifactUpload(HttpExchange exchange, String projectId,
                                        String uploadId) throws IOException {
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(projectId);
        Map<String, Object> body = ControlPlaneHttpSupport.readObject(exchange);
        if (!ControlPlaneHttpSupport.requiredBoolean(body, "authorized")) {
            throw new ControlPlaneHttpSupport.ApiException(403, "AUTHORIZATION_REQUIRED",
                    "artifact upload completion requires explicit authorization");
        }
        ArtifactDescriptor descriptor = host.artifactUploadService.complete(projectId, uploadId);
        host.store.registerArtifact(project, descriptor, actor(exchange).operatorId());
        host.artifactUploadService.finish(projectId, uploadId);
        ControlPlaneHttpSupport.sendJson(exchange, 201, artifactMap(artifactDto(projectId, descriptor)));
    }
    public void cancelArtifactUpload(HttpExchange exchange, String projectId,
                                      String uploadId) throws IOException {
        host.store.requireProject(projectId);
        host.artifactUploadService.cancel(projectId, uploadId);
        ControlPlaneHttpSupport.sendEmpty(exchange, 204);
    }
    public void listArtifacts(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(projectId);
        List<Object> artifacts = new ArrayList<>();
        for (ArtifactDescriptor descriptor : host.store.artifacts(project)) artifacts.add(artifactMap(artifactDto(projectId, descriptor)));
        Map<String, Object> result = envelope(projectId, artifacts);
        result.put("artifacts", artifacts);
        result.put("artifactDigest", artifacts.isEmpty() ? "unscanned" : ((Map<?, ?>) artifacts.get(0)).get("artifactDigest"));
        result.put("scanId", project.latestScanId() == null ? "unscanned" : project.latestScanId());
        ControlPlaneHttpSupport.sendJson(exchange, 200, result);
    }
    public void listEntries(HttpExchange exchange, String projectId) throws IOException {
        ControlPlaneStore.ProjectRecord project = host.store.requireProject(projectId);
        String scanId = ControlPlaneHttpSupport.query(exchange.getRequestURI(), "scanId");
        ControlPlaneStore.ScanRecord scan = scanId == null ? latestScan(project) : host.store.scan(scanId);
        if (scan == null || !projectId.equals(scan.dto().projectId())) {
            Map<String, Object> result = envelope(projectId, List.of());
            result.put("entries", List.of());
            result.put("verificationStatus", "UNREACHED");
            result.put("artifactDigest", "unscanned");
            result.put("scanId", "unscanned");
            ControlPlaneHttpSupport.sendJson(exchange, 200, result);
            return;
        }
        List<Object> entries = new ArrayList<>();
        for (ApiDtos.EntryDto entry : scan.dto().entries()) entries.add(entryMap(entry));
        ControlPlaneHttpSupport.sendJson(exchange, 200, envelope(scan, "entries", entries));
    }
    public void listAudit(HttpExchange exchange, String projectId) throws IOException {
        List<Object> items = new ArrayList<>();
        for (var event : host.store.auditEvents(projectId)) items.add(AiJobHttpHandlers.auditMap(event));
        ControlPlaneHttpSupport.sendJson(exchange, 200, stringEnvelope("auditEvents", items));
    }
    public void sendHealth(HttpExchange exchange) throws IOException {
        ControlPlaneHttpSupport.sendJson(exchange, 200, health());
    }

    public Map<String, Object> health() {
        VerifiedStatusGate.Decision verified = VerifiedStatusGate.forTrustedDockerHealth();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        body.put("status", "UP");
        body.put("service", "jvm-sentinel-control-plane");
        body.put("persistenceMode", host.store.persistenceMode());
        body.put("analysisMode", "STATIC_METADATA_ONLY");
        // 本地 MVP 单独暴露 TRUSTED_DOCKER worker；VERIFIED 保持关闭。
        body.put("dynamicExecutionMode", verified.dynamicExecutionMode());
        body.put("verifiedAllowed", verified.allowed());
        body.put("verifiedReasonCode", verified.reasonCode());
        body.put("maxVerificationStatus", verified.verificationStatus());
        body.put("workerContractVersion", WorkerControlPlaneApi.CONTRACT_VERSION);
        body.put("dependencyMode", ApiDtos.MOCK);
        body.put("bindAddress", host.bindAddress.getHostString());
        body.put("port", host.bindAddress.getPort());
        return body;
    }
    public void requirePermission(HttpExchange exchange, Permission permission) {
        AuthContext context = actor(exchange);
        Authorizer.Decision decision = host.authorizer.authorize(
                context, com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                permission);
        if (!decision.allowed()) {
            throw new ControlPlaneHttpSupport.ApiException(403, "PERMISSION_DENIED", "operator permission is required");
        }
    }
    AuthContext actor(HttpExchange exchange) {
        String supplied = exchange.getRequestHeaders().getFirst("X-Sentinel-Authorization");
        if (supplied == null || supplied.isBlank()) {
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
                supplied = authorization.substring(7).trim();
            }
        }
        if (supplied == null || supplied.isBlank() || ControlPlaneHttpSupport.constantTimeEquals(host.workerToken, supplied)) {
            throw new ControlPlaneHttpSupport.ApiException(401, "AUTHORIZATION_REQUIRED", "a local authorization token is required");
        }
        if ("SQLITE".equals(host.store.persistenceMode())) {
            var operator = host.store.authenticateOperator(supplied);
            if (operator == null) {
                throw new ControlPlaneHttpSupport.ApiException(401, "AUTHORIZATION_REQUIRED", "a local authorization token is required");
            }
            return AuthContext.authenticated(operator.operatorId(),
                    com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                    Set.of(operator.role()));
        }
        if (!ControlPlaneHttpSupport.constantTimeEquals(host.mutationToken, supplied)) {
            throw new ControlPlaneHttpSupport.ApiException(401, "AUTHORIZATION_REQUIRED", "a local authorization token is required");
        }
        return AuthContext.authenticated("local-admin",
                com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.LOCAL_WORKSPACE,
                Set.of(OperatorRole.ADMINISTRATOR));
    }
    public AgentRole role(String value) {
        if (value == null) throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_ROLE", "AI role is required");
        try { return AgentRole.valueOf(value); }
        catch (IllegalArgumentException invalid) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_ROLE", "unsupported AI role");
        }
    }
    static OperatorRole operatorRole(String value) {
        if (value == null) throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_ROLE", "operator role is required");
        try { return OperatorRole.valueOf(value); }
        catch (IllegalArgumentException invalid) {
            throw new ControlPlaneHttpSupport.ApiException(400, "INVALID_ROLE", "unsupported operator role");
        }
    }
    ApiDtos.ProjectDto projectDto(ControlPlaneStore.ProjectRecord project) {
        List<ApiDtos.ArtifactDto> artifacts = new ArrayList<>();
        for (ArtifactDescriptor descriptor : host.store.artifacts(project)) artifacts.add(artifactDto(project.projectId(), descriptor));
        ControlPlaneStore.ScanRecord latest = latestScan(project);
        String status = latest == null ? "UNREACHED" : latest.dto().verificationStatus();
        List<String> refs = latest == null ? List.of() : latest.dto().evidenceRefs();
        return new ApiDtos.ProjectDto(ApiDtos.SCHEMA_VERSION, project.projectId(), project.name(), project.createdAt(),
                status, ApiDtos.MOCK, refs, artifacts);
    }
    Map<String, Object> projectMap(ControlPlaneStore.ProjectRecord project) {
        ApiDtos.ProjectDto dto = projectDto(project);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion());
        result.put("projectId", dto.projectId());
        result.put("name", dto.name());
        result.put("status", project.status());
        result.put("createdAt", dto.createdAt());
        result.put("updatedAt", project.updatedAt());
        result.put("verificationStatus", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode());
        result.put("evidenceRefs", dto.evidenceRefs());
        List<Object> artifacts = new ArrayList<>();
        for (ApiDtos.ArtifactDto artifact : dto.artifacts()) artifacts.add(artifactMap(artifact));
        result.put("artifacts", artifacts);
        ControlPlaneStore.ScanRecord latest = latestScan(project);
        result.put("artifactDigest", latest == null
                ? (artifacts.isEmpty() ? "unscanned" : ((Map<?, ?>) artifacts.get(0)).get("artifactDigest"))
                : latest.dto().artifactDigest());
        result.put("scanId", latest == null ? "unscanned" : latest.dto().scanId());
        return result;
    }
    ApiDtos.ArtifactDto artifactDto(String projectId, ArtifactDescriptor descriptor) {
        return new ApiDtos.ArtifactDto(ApiDtos.SCHEMA_VERSION, projectId, descriptor.artifactId(),
                descriptor.type().name(), descriptor.sha256(), descriptor.sizeBytes(), descriptor.staticOnly(),
                descriptor.registeredAt().toString(), ApiDtos.STATIC_INFERRED, ApiDtos.MOCK, List.of(),
                descriptor.originalFileName());
    }
    static Map<String, Object> artifactMap(ApiDtos.ArtifactDto dto) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", dto.schemaVersion()); result.put("projectId", dto.projectId());
        result.put("artifactId", dto.artifactId()); result.put("artifactType", dto.artifactType());
        result.put("artifactDigest", dto.artifactDigest()); result.put("sha256", dto.artifactDigest());
        result.put("sizeBytes", dto.sizeBytes()); result.put("staticOnly", dto.staticOnly());
        result.put("registeredAt", dto.registeredAt()); result.put("verificationStatus", dto.verificationStatus());
        result.put("dependencyMode", dto.dependencyMode()); result.put("evidenceRefs", dto.evidenceRefs());
        result.put("originalFileName", dto.originalFileName());
        result.put("fileName", dto.originalFileName());
        result.put("displayName", dto.displayName());
        return result;
    }
    static Map<String, Object> uploadSessionMap(ArtifactUploadService.UploadSession session) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", ApiDtos.SCHEMA_VERSION);
        result.put("uploadId", session.uploadId());
        result.put("projectId", session.projectId());
        result.put("fileName", session.fileName());
        result.put("sizeBytes", session.sizeBytes());
        result.put("sha256", session.sha256());
        result.put("nextOffset", session.nextOffset());
        result.put("expiresAt", session.expiresAt().toString());
        result.put("recommendedChunkBytes", session.recommendedChunkBytes());
        result.put("maxChunkBytes", session.maxChunkBytes());
        return result;
    }
    static Map<String, Object> operatorMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.OperatorData operator,
            String personalAccessToken) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("operatorId", operator.operatorId());
        result.put("username", operator.username());
        result.put("role", operator.role().name());
        result.put("createdAt", operator.createdAt());
        result.put("updatedAt", operator.updatedAt());
        if (personalAccessToken != null) result.put("personalAccessToken", personalAccessToken);
        return result;
    }
    public static Map<String, Object> providerMap(
            com.aq.jvmsentinel.control.persistence.SQLiteControlPlanePersistence.ProviderData provider) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", 1);
        result.put("providerId", provider.providerId());
        result.put("name", provider.name());
        result.put("kind", provider.kind().name());
        result.put("baseUrl", provider.baseUrl());
        if (provider.model() != null) result.put("model", provider.model());
        result.put("enabled", provider.enabled());
        result.put("hasCredential", provider.hasCredential());
        result.put("updatedAt", provider.updatedAt());
        return result;
    }
    static Map<String, Object> inventoryMap(ModelInventory inventory) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schemaVersion", inventory.schemaVersion());
        result.put("workspaceId", inventory.workspaceId());
        result.put("providerId", inventory.providerId());
        result.put("protocol", inventory.protocol().name());
        result.put("semantics", inventory.semantics().name());
        result.put("fetchedAt", inventory.fetchedAt().toString());
        List<Object> models = new ArrayList<>();
        for (var model : inventory.models()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("schemaVersion", model.schemaVersion());
            item.put("workspaceId", model.workspaceId());
            item.put("modelId", model.modelId());
            item.put("providerId", model.providerId());
            item.put("providerModelName", model.providerModelName());
            item.put("contextWindowTokens", model.contextWindowTokens());
            item.put("enabled", model.enabled());
            item.put("createdAt", model.createdAt().toString());
            item.put("updatedAt", model.updatedAt().toString());
            models.add(item);
        }
        result.put("models", models);
        return result;
    }
}
