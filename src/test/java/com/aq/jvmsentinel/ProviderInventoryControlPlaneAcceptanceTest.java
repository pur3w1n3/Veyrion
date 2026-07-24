package com.aq.jvmsentinel;

import com.aq.jvmsentinel.control.ControlPlaneServer;
import com.aq.jvmsentinel.control.JsonCodec;
import com.aq.jvmsentinel.provider.ProviderContracts.InventorySemantics;
import com.aq.jvmsentinel.provider.ProviderContracts.ModelDefinition;
import com.aq.jvmsentinel.provider.ProviderContracts.ModelInventory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/** Main-style HTTP acceptance for provider inventory authorization, redaction, and DTO semantics. */
public final class ProviderInventoryControlPlaneAcceptanceTest {
    private static final String SECRET = "inventory-control-secret-913ac";

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("veyrion-provider-inventory-control");
        Path database = root.resolve("state").resolve("control-plane.db");
        String bootstrap = "provider-inventory-bootstrap";
        HttpClient client = HttpClient.newHttpClient();
        AtomicReference<byte[]> observedCredential = new AtomicReference<>();

        ControlPlaneServer.ProviderInventoryService inventoryService = (provider, credential) -> {
            check(SECRET.equals(new String(credential, StandardCharsets.UTF_8)),
                    "mock receives the decrypted credential");
            observedCredential.set(credential);
            if (provider.displayName().contains("Failure")) {
                throw new IllegalStateException("remote failure " + SECRET);
            }
            Instant now = Instant.parse("2026-07-24T09:00:00Z");
            ModelDefinition model = new ModelDefinition(1, provider.workspaceId(),
                    "inventory-model-a", provider.providerId(), "provider-model-a",
                    0, false, now, now);
            return new ModelInventory(1, provider.workspaceId(), provider.providerId(),
                    provider.kind().protocol(), List.of(model),
                    InventorySemantics.REMOTE_INVENTORY_ONLY, now);
        };

        try (ControlPlaneServer server = new ControlPlaneServer(
                root, 0, bootstrap, database, inventoryService).start()) {
            String viewerPat = text(ok(send(client, uri(server, "/operators"), "POST",
                    "{\"username\":\"inventory-viewer\",\"role\":\"VIEWER\"}", bootstrap)),
                    "personalAccessToken");

            String providerId = createProvider(client, server, bootstrap, "Inventory Provider",
                    "OPENAI_CHAT", true, SECRET);
            URI getInventory = uri(server, "/providers/" + providerId + "/models");
            URI postInventory = uri(server, "/providers/" + providerId + "/models/refresh");

            check(send(client, getInventory, "GET", "", null).statusCode() >= 400,
                    "GET cannot trigger inventory network activity");
            check(send(client, getInventory, "GET", "", viewerPat).statusCode() >= 400,
                    "authenticated GET cannot trigger inventory network activity");
            check(send(client, postInventory, "POST", "{}", viewerPat).statusCode() == 403,
                    "viewer cannot trigger POST inventory refresh");
            check(send(client, getInventory, "GET", "", server.workerToken()).statusCode() >= 400,
                    "Worker GET cannot enter an inventory mutation route");
            check(observedCredential.get() == null,
                    "all GET variants leave the injected inventory transport untouched");
            check(send(client, postInventory, "POST", "{}", server.workerToken()).statusCode() == 401,
                    "Worker token cannot trigger POST inventory refresh");

            HttpResponse<String> getResponse = send(client, postInventory, "POST", "{}", bootstrap);
            Map<String, Object> inventory = ok(getResponse);
            check("REMOTE_INVENTORY_ONLY".equals(inventory.get("semantics")),
                    "result is explicitly inventory-only");
            check("OPENAI_CHAT".equals(inventory.get("protocol")),
                    "result protocol is explicit");
            Map<?, ?> model = first((List<?>) inventory.get("models"));
            check("provider-model-a".equals(model.get("providerModelName"))
                            && Boolean.FALSE.equals(model.get("enabled"))
                            && model.get("contextWindowTokens") instanceof Number context
                            && context.intValue() == 0,
                    "result DTO cannot enable, bind, or claim model context");
            check(!getResponse.body().contains(SECRET), "successful response does not leak credential");
            check(allZero(observedCredential.get()), "decrypted credential is cleared after POST");

            observedCredential.set(null);
            check(send(client, postInventory, "POST", "{}", bootstrap).statusCode() == 200,
                    "administrator can trigger POST inventory refresh");
            check(allZero(observedCredential.get()), "decrypted credential is cleared after POST");

            String disabled = createProvider(client, server, bootstrap, "Disabled Provider",
                    "OPENAI_CHAT", false, SECRET);
            HttpResponse<String> disabledResponse = send(client,
                    uri(server, "/providers/" + disabled + "/models/refresh"), "POST", "{}", bootstrap);
            check(disabledResponse.statusCode() == 409
                            && disabledResponse.body().contains("PROVIDER_DISABLED"),
                    "disabled provider fails closed");

            String missing = createProvider(client, server, bootstrap, "Missing Credential",
                    "ANTHROPIC_MESSAGES", true, null);
            HttpResponse<String> missingResponse = send(client,
                    uri(server, "/providers/" + missing + "/models/refresh"), "POST", "{}", bootstrap);
            check(missingResponse.statusCode() == 409
                            && missingResponse.body().contains("PROVIDER_CREDENTIAL_REQUIRED"),
                    "missing credential fails closed");

            String azure = createProvider(client, server, bootstrap, "Azure Provider",
                    "AZURE_OPENAI", true, SECRET);
            HttpResponse<String> azureResponse = send(client,
                    uri(server, "/providers/" + azure + "/models/refresh"), "POST", "{}", bootstrap);
            check(azureResponse.statusCode() == 422
                            && azureResponse.body().contains("PROVIDER_INVENTORY_UNSUPPORTED"),
                    "unsupported Azure inventory fails closed");

            String failure = createProvider(client, server, bootstrap, "Protocol Failure",
                    "OPENAI_CHAT", true, SECRET);
            HttpResponse<String> failureResponse = send(client,
                    uri(server, "/providers/" + failure + "/models/refresh"), "POST", "{}", bootstrap);
            check(failureResponse.statusCode() == 502
                            && failureResponse.body().contains("PROVIDER_INVENTORY_FAILED")
                            && !failureResponse.body().contains(SECRET),
                    "provider protocol failure is explicit and redacted");
            check(allZero(observedCredential.get()), "decrypted credential is cleared after failure");

            String providers = send(client, uri(server, "/providers"), "GET", "", bootstrap).body();
            String audits = send(client, uri(server, "/audit-events"), "GET", "", bootstrap).body();
            check(!providers.contains(SECRET) && !audits.contains(SECRET),
                    "provider responses and audit output contain no credential");
        }

        System.out.println("ProviderInventoryControlPlaneAcceptanceTest: PASS");
    }

    private static String createProvider(HttpClient client, ControlPlaneServer server, String token,
                                         String name, String kind, boolean enabled, String apiKey)
            throws Exception {
        String key = apiKey == null ? "" : ",\"apiKey\":\"" + apiKey + "\"";
        String body = "{\"name\":\"" + name + "\",\"kind\":\"" + kind
                + "\",\"baseUrl\":\"https://provider.invalid/v1\",\"enabled\":" + enabled + key + "}";
        return text(ok(send(client, uri(server, "/providers"), "POST", body, token)), "providerId");
    }

    private static URI uri(ControlPlaneServer server, String path) {
        return URI.create(server.baseUri() + path);
    }

    private static HttpResponse<String> send(HttpClient client, URI uri, String method,
                                             String json, String token) throws Exception {
        HttpRequest.BodyPublisher publisher = json.isEmpty()
                ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json);
        HttpRequest.Builder request = HttpRequest.newBuilder(uri).header("Content-Type", "application/json");
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(request.method(method, publisher).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Map<String, Object> ok(HttpResponse<String> response) {
        check(response.statusCode() >= 200 && response.statusCode() < 300,
                "unexpected response " + response.statusCode() + ": " + response.body());
        return JsonCodec.parseObject(response.body());
    }

    private static Map<?, ?> first(List<?> values) {
        check(values != null && values.size() == 1 && values.get(0) instanceof Map<?, ?>,
                "expected one model object");
        return (Map<?, ?>) values.get(0);
    }

    private static String text(Map<?, ?> value, String key) {
        Object result = value.get(key);
        check(result instanceof String && !((String) result).isBlank(), key + " is required");
        return (String) result;
    }

    private static boolean allZero(byte[] value) {
        if (value == null || value.length == 0) return false;
        for (byte item : value) if (item != 0) return false;
        return true;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
