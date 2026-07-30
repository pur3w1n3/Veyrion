package com.aq.jvmsentinel.control.routing;

import com.aq.jvmsentinel.provider.AgentRole;
import com.aq.jvmsentinel.security.auth.Permission;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

/** 由 {@link RouteTable} 使用的包可见 handler 表面。 */
public interface ControlPlaneRouteActions {
    final class RouteException extends RuntimeException {
        public final int status;
        public final String code;
        public RouteException(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }
    }

    void requirePermission(HttpExchange exchange, Permission permission);
    void sendHealth(HttpExchange exchange) throws IOException;
    String query(URI uri, String name);
    AgentRole role(String value);

    void createProject(HttpExchange exchange) throws IOException;
    void listProjects(HttpExchange exchange) throws IOException;
    void sendProject(HttpExchange exchange, String projectId) throws IOException;
    void updateProject(HttpExchange exchange, String projectId) throws IOException;
    void deleteProject(HttpExchange exchange, String projectId) throws IOException;
    void registerArtifact(HttpExchange exchange, String projectId) throws IOException;
    void listArtifacts(HttpExchange exchange, String projectId) throws IOException;
    void initializeArtifactUpload(HttpExchange exchange, String projectId) throws IOException;
    void appendArtifactUpload(HttpExchange exchange, String projectId, String uploadId) throws IOException;
    void cancelArtifactUpload(HttpExchange exchange, String projectId, String uploadId) throws IOException;
    void completeArtifactUpload(HttpExchange exchange, String projectId, String uploadId) throws IOException;
    void listEntries(HttpExchange exchange, String projectId) throws IOException;
    void startAudit(HttpExchange exchange, String projectId) throws IOException;
    void retryAuditStage(HttpExchange exchange, String projectId) throws IOException;
    void createScan(HttpExchange exchange, String projectId) throws IOException;
    void listScans(HttpExchange exchange, String projectId) throws IOException;
    void updateScan(HttpExchange exchange, String scanId) throws IOException;
    void deleteScan(HttpExchange exchange, String projectId, String scanId) throws IOException;
    void dashboard(HttpExchange exchange, String projectId) throws IOException;
    void listEvidence(HttpExchange exchange, String projectId) throws IOException;
    void sendScan(HttpExchange exchange, String scanId) throws IOException;
    void sendScanCoverage(HttpExchange exchange, String scanId) throws IOException;
    void sendScanEvidenceGraph(HttpExchange exchange, String scanId) throws IOException;
    void sendScanHypotheses(HttpExchange exchange, String scanId) throws IOException;
    void sendScanAiMemory(HttpExchange exchange, String scanId) throws IOException;
    void streamEvents(HttpExchange exchange, String scanId) throws IOException;
    void listDynamicTasks(HttpExchange exchange, String scanId) throws IOException;
    void createDynamicTask(HttpExchange exchange, String scanId) throws IOException;
    void listPaths(HttpExchange exchange, String scanId) throws IOException;
    void listScanEvidence(HttpExchange exchange, String scanId) throws IOException;
    void listScanFindings(HttpExchange exchange, String scanId) throws IOException;
    void sendPath(HttpExchange exchange, String scanId, String pathId) throws IOException;
    void sendFinding(HttpExchange exchange, String findingId) throws IOException;
    void replayFinding(HttpExchange exchange, String findingId) throws IOException;
    void focusEntryProbe(HttpExchange exchange, String scanId, String entryId) throws IOException;
    void replaySqlExperimentCard(HttpExchange exchange, String scanId, String cardId) throws IOException;
    void listOperators(HttpExchange exchange) throws IOException;
    void createOperator(HttpExchange exchange) throws IOException;
    void updateOperator(HttpExchange exchange, String operatorId) throws IOException;
    void listProviders(HttpExchange exchange) throws IOException;
    void createProvider(HttpExchange exchange) throws IOException;
    void updateProvider(HttpExchange exchange, String providerId) throws IOException;
    void deleteProvider(HttpExchange exchange, String providerId) throws IOException;
    void detectProviderProtocol(HttpExchange exchange) throws IOException;
    void refreshProviderModels(HttpExchange exchange, String providerId) throws IOException;
    void listRoleAssignments(HttpExchange exchange, String projectId) throws IOException;
    void sendRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException;
    void saveRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException;
    void deleteRoleAssignment(HttpExchange exchange, String projectId, AgentRole role) throws IOException;
    void listAiJobs(HttpExchange exchange, String projectId) throws IOException;
    void createAiJob(HttpExchange exchange, String projectId) throws IOException;
    void listAiJobEvents(HttpExchange exchange, String jobId) throws IOException;
    void sendAiJob(HttpExchange exchange, String jobId) throws IOException;
    void updateAiJob(HttpExchange exchange, String jobId) throws IOException;
    void deleteAiJob(HttpExchange exchange, String jobId) throws IOException;
    void listAudit(HttpExchange exchange, String projectId) throws IOException;
    void sendEvidence(HttpExchange exchange, String evidenceId) throws IOException;
    void listChains(HttpExchange exchange) throws IOException;
}
