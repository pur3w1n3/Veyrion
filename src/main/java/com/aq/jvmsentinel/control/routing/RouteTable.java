package com.aq.jvmsentinel.control.routing;

import com.aq.jvmsentinel.security.auth.Permission;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

/**
 * Declarative HTTP route dispatch for ControlPlaneServer.
 * Handlers remain implemented by {@link ControlPlaneRouteActions}.
 */
public final class RouteTable {
    private RouteTable() {}

    public static void dispatch(ControlPlaneRouteActions actions, HttpExchange exchange, List<String> path)
            throws IOException {
        String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
        if (path.size() == 1 && "health".equals(path.get(0)) && "GET".equals(method)) {
            actions.sendHealth(exchange);
            return;
        }
        if (path.size() == 1 && "projects".equals(path.get(0))) {
            if ("POST".equals(method)) { actions.requirePermission(exchange, Permission.MANAGE_PROJECTS); actions.createProject(exchange); return; }
            if ("GET".equals(method)) { actions.listProjects(exchange); return; }
        }
        if (path.size() == 2 && "projects".equals(path.get(0))) {
            if ("GET".equals(method)) { actions.sendProject(exchange, path.get(1)); return; }
            if ("PATCH".equals(method)) {
                actions.requirePermission(exchange, Permission.MANAGE_PROJECTS);
                actions.updateProject(exchange, path.get(1));
                return;
            }
            if ("DELETE".equals(method)) {
                actions.requirePermission(exchange, Permission.MANAGE_PROJECTS);
                actions.deleteProject(exchange, path.get(1));
                return;
            }
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "artifacts".equals(path.get(2))) {
            if ("POST".equals(method)) { actions.requirePermission(exchange, Permission.MANAGE_PROJECTS); actions.registerArtifact(exchange, path.get(1)); return; }
            if ("GET".equals(method)) { actions.listArtifacts(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "artifact-uploads".equals(path.get(2))
                && "POST".equals(method)) {
            actions.requirePermission(exchange, Permission.MANAGE_PROJECTS);
            actions.initializeArtifactUpload(exchange, path.get(1));
            return;
        }
        if (path.size() == 4 && "projects".equals(path.get(0)) && "artifact-uploads".equals(path.get(2))) {
            actions.requirePermission(exchange, Permission.MANAGE_PROJECTS);
            if ("PUT".equals(method)) {
                actions.appendArtifactUpload(exchange, path.get(1), path.get(3));
                return;
            }
            if ("DELETE".equals(method)) {
                actions.cancelArtifactUpload(exchange, path.get(1), path.get(3));
                return;
            }
        }
        if (path.size() == 5 && "projects".equals(path.get(0)) && "artifact-uploads".equals(path.get(2))
                && "complete".equals(path.get(4)) && "POST".equals(method)) {
            actions.requirePermission(exchange, Permission.MANAGE_PROJECTS);
            actions.completeArtifactUpload(exchange, path.get(1), path.get(3));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "entries".equals(path.get(2))
                && "GET".equals(method)) {
            actions.listEntries(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "audit-runs".equals(path.get(2))
                && "POST".equals(method)) {
            actions.requirePermission(exchange, Permission.RUN_SCANS);
            actions.requirePermission(exchange, Permission.RUN_AI_JOBS);
            actions.startAudit(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "audit-stage-retries".equals(path.get(2))
                && "POST".equals(method)) {
            actions.requirePermission(exchange, Permission.RUN_SCANS);
            actions.requirePermission(exchange, Permission.RUN_AI_JOBS);
            actions.retryAuditStage(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "scans".equals(path.get(2))) {
            if ("POST".equals(method)) { actions.requirePermission(exchange, Permission.RUN_SCANS); actions.createScan(exchange, path.get(1)); return; }
            if ("GET".equals(method)) { actions.listScans(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "dashboard".equals(path.get(2))
                && "GET".equals(method)) {
            actions.dashboard(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0)) && "evidence".equals(path.get(2))
                && "GET".equals(method)) {
            actions.listEvidence(exchange, path.get(1));
            return;
        }
        if (path.size() == 2 && "scans".equals(path.get(0))) {
            if ("GET".equals(method)) { actions.sendScan(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "coverage".equals(path.get(2))
                && "GET".equals(method)) {
            actions.sendScanCoverage(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "evidence-graph".equals(path.get(2))
                && "GET".equals(method)) {
            actions.sendScanEvidenceGraph(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "hypotheses".equals(path.get(2))
                && "GET".equals(method)) {
            actions.sendScanHypotheses(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "events".equals(path.get(2))
                && "GET".equals(method)) {
            actions.streamEvents(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "dynamic-tasks".equals(path.get(2))) {
            actions.requirePermission(exchange, "GET".equals(method) ? Permission.READ_AUDIT : Permission.RUN_SCANS);
            if ("GET".equals(method)) { actions.listDynamicTasks(exchange, path.get(1)); return; }
            if ("POST".equals(method)) { actions.createDynamicTask(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "paths".equals(path.get(2))
                && "GET".equals(method)) {
            actions.listPaths(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "evidence".equals(path.get(2))
                && "GET".equals(method)) {
            actions.listScanEvidence(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "scans".equals(path.get(0)) && "findings".equals(path.get(2))
                && "GET".equals(method)) {
            actions.listScanFindings(exchange, path.get(1));
            return;
        }
        if (path.size() == 4 && "scans".equals(path.get(0)) && "paths".equals(path.get(2))
                && "GET".equals(method)) {
            actions.sendPath(exchange, path.get(1), path.get(3));
            return;
        }
        if (path.size() == 2 && "findings".equals(path.get(0)) && "GET".equals(method)) {
            actions.sendFinding(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "findings".equals(path.get(0)) && "replay".equals(path.get(2))) {
            if ("POST".equals(method)) { actions.requirePermission(exchange, Permission.RUN_SCANS); actions.replayFinding(exchange, path.get(1)); return; }
        }
        if (path.size() == 5 && "scans".equals(path.get(0)) && "entries".equals(path.get(2))
                && "focus-probe".equals(path.get(4)) && "POST".equals(method)) {
            actions.requirePermission(exchange, Permission.RUN_SCANS);
            actions.focusEntryProbe(exchange, path.get(1), path.get(3));
            return;
        }
        if (path.size() == 5 && "scans".equals(path.get(0)) && "experiment-cards".equals(path.get(2))
                && "replay".equals(path.get(4)) && "POST".equals(method)) {
            actions.requirePermission(exchange, Permission.RUN_SCANS);
            actions.replaySqlExperimentCard(exchange, path.get(1), path.get(3));
            return;
        }
        if (path.size() == 1 && "operators".equals(path.get(0))) {
            actions.requirePermission(exchange, Permission.MANAGE_OPERATOR_ACCESS);
            if ("GET".equals(method)) { actions.listOperators(exchange); return; }
            if ("POST".equals(method)) { actions.createOperator(exchange); return; }
        }
        if (path.size() == 2 && "operators".equals(path.get(0)) && "PATCH".equals(method)) {
            actions.requirePermission(exchange, Permission.MANAGE_OPERATOR_ACCESS);
            actions.updateOperator(exchange, path.get(1));
            return;
        }
        if (path.size() == 1 && "providers".equals(path.get(0))) {
            actions.requirePermission(exchange, "GET".equals(method)
                    ? Permission.READ_SECURITY_CONFIGURATION : Permission.MANAGE_PROVIDERS);
            if ("GET".equals(method)) { actions.listProviders(exchange); return; }
            if ("POST".equals(method)) { actions.createProvider(exchange); return; }
        }
        if (path.size() == 2 && "providers".equals(path.get(0))) {
            actions.requirePermission(exchange, Permission.MANAGE_PROVIDERS);
            if ("PATCH".equals(method)) { actions.updateProvider(exchange, path.get(1)); return; }
            if ("DELETE".equals(method)) { actions.deleteProvider(exchange, path.get(1)); return; }
        }
        if (path.size() == 4 && "providers".equals(path.get(0))
                && "models".equals(path.get(2)) && "refresh".equals(path.get(3))
                && "POST".equals(method)) {
            actions.requirePermission(exchange, Permission.MANAGE_PROVIDERS);
            actions.refreshProviderModels(exchange, path.get(1));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0))
                && "role-assignments".equals(path.get(2)) && "GET".equals(method)) {
            actions.requirePermission(exchange, Permission.READ_SECURITY_CONFIGURATION);
            actions.listRoleAssignments(exchange, path.get(1));
            return;
        }
        if (path.size() == 4 && "projects".equals(path.get(0))
                && "role-assignments".equals(path.get(2))) {
            if ("GET".equals(method)) {
                actions.requirePermission(exchange, Permission.READ_SECURITY_CONFIGURATION);
                actions.sendRoleAssignment(exchange, path.get(1), actions.role(path.get(3)));
                return;
            }
            actions.requirePermission(exchange, Permission.ASSIGN_AGENT_ROLES);
            if ("PATCH".equals(method)) { actions.saveRoleAssignment(exchange, path.get(1), actions.role(path.get(3))); return; }
            if ("DELETE".equals(method)) { actions.deleteRoleAssignment(exchange, path.get(1), actions.role(path.get(3))); return; }
        }
        if (path.size() == 3 && "projects".equals(path.get(0))
                && "ai-jobs".equals(path.get(2))) {
            actions.requirePermission(exchange, "GET".equals(method) ? Permission.READ_SECURITY_CONFIGURATION : Permission.RUN_AI_JOBS);
            if ("GET".equals(method)) { actions.listAiJobs(exchange, path.get(1)); return; }
            if ("POST".equals(method)) { actions.createAiJob(exchange, path.get(1)); return; }
        }
        if (path.size() == 3 && "ai-jobs".equals(path.get(0))
                && "events".equals(path.get(2)) && "GET".equals(method)) {
            actions.requirePermission(exchange, Permission.READ_SECURITY_CONFIGURATION);
            actions.listAiJobEvents(exchange, path.get(1));
            return;
        }
        if (path.size() == 2 && "ai-jobs".equals(path.get(0))) {
            actions.requirePermission(exchange, "GET".equals(method) ? Permission.READ_SECURITY_CONFIGURATION : Permission.RUN_AI_JOBS);
            if ("GET".equals(method)) { actions.sendAiJob(exchange, path.get(1)); return; }
            if ("PATCH".equals(method)) { actions.updateAiJob(exchange, path.get(1)); return; }
            if ("DELETE".equals(method)) { actions.deleteAiJob(exchange, path.get(1)); return; }
        }
        if (path.size() == 1 && "audit-events".equals(path.get(0)) && "GET".equals(method)) {
            actions.requirePermission(exchange, Permission.READ_AUDIT);
            actions.listAudit(exchange, actions.query(exchange.getRequestURI(), "projectId"));
            return;
        }
        if (path.size() == 3 && "projects".equals(path.get(0))
                && "audit-events".equals(path.get(2)) && "GET".equals(method)) {
            actions.requirePermission(exchange, Permission.READ_AUDIT);
            actions.listAudit(exchange, path.get(1));
            return;
        }
        if (path.size() == 2 && "evidence".equals(path.get(0)) && "GET".equals(method)) {
            actions.sendEvidence(exchange, path.get(1));
            return;
        }
        if (path.size() == 1 && "attack-chains".equals(path.get(0)) && "GET".equals(method)) {
            actions.listChains(exchange);
            return;
        }
        throw new ControlPlaneRouteActions.RouteException(405, "METHOD_NOT_ALLOWED", "route or method is not allowed");
    }
}
