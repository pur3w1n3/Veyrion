package com.aq.jvmsentinel.worker;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 按 projectId 公平挑选可派发的 QUEUED TRUSTED_DOCKER 任务。
 *
 * <p>同 project 受 {@link LocalWorkerQuota#maxPerProjectConcurrency()} 限流；
 * 全局受 {@link LocalWorkerQuota#maxGlobalConcurrency()} 限流；
 * 轮转起始 project，避免单工作区霸占调度窗口。</p>
 */
public final class ProjectFairTaskDispatcher {
    private ProjectFairTaskDispatcher() { }

    public static List<TaskScope> select(
            List<WorkerControlPlaneClient.TaskDescriptor> tasks,
            Set<TaskScope> inFlight,
            Map<String, Integer> perProjectInFlight,
            LocalWorkerQuota quota,
            String rotateAfterProjectId
    ) {
        Objects.requireNonNull(tasks, "tasks");
        Objects.requireNonNull(inFlight, "inFlight");
        Objects.requireNonNull(perProjectInFlight, "perProjectInFlight");
        Objects.requireNonNull(quota, "quota");

        int globalInFlight = inFlight.size();
        int globalSlots = quota.maxGlobalConcurrency() - globalInFlight;
        if (globalSlots <= 0) {
            return List.of();
        }

        Map<String, List<TaskScope>> byProject = new LinkedHashMap<>();
        for (WorkerControlPlaneClient.TaskDescriptor task : tasks) {
            if (!isEligible(task) || inFlight.contains(task.scope())) {
                continue;
            }
            byProject.computeIfAbsent(task.scope().projectId(), ignored -> new ArrayList<>())
                    .add(task.scope());
        }
        if (byProject.isEmpty()) {
            return List.of();
        }

        List<String> projectOrder = new ArrayList<>(byProject.keySet());
        rotateProjects(projectOrder, rotateAfterProjectId);

        List<TaskScope> selected = new ArrayList<>();
        int remainingGlobal = globalSlots;
        for (String projectId : projectOrder) {
            if (remainingGlobal <= 0) {
                break;
            }
            int projectRunning = Math.max(0, perProjectInFlight.getOrDefault(projectId, 0));
            int projectSlots = quota.maxPerProjectConcurrency() - projectRunning;
            if (projectSlots <= 0) {
                continue;
            }
            List<TaskScope> queue = byProject.get(projectId);
            int take = Math.min(projectSlots, Math.min(remainingGlobal, queue.size()));
            for (int i = 0; i < take; i++) {
                selected.add(queue.get(i));
            }
            remainingGlobal -= take;
        }
        return List.copyOf(selected);
    }

    static boolean isEligible(WorkerControlPlaneClient.TaskDescriptor task) {
        return task != null
                && task.lifecycle() == TaskLifecycle.QUEUED
                && !task.fixtureOnly()
                && task.authorized()
                && task.requiredCapability() == WorkerCapability.TRUSTED_DOCKER;
    }

    private static void rotateProjects(List<String> projectOrder, String rotateAfterProjectId) {
        if (rotateAfterProjectId == null || rotateAfterProjectId.isBlank() || projectOrder.size() < 2) {
            return;
        }
        int index = projectOrder.indexOf(rotateAfterProjectId);
        if (index < 0) {
            return;
        }
        int pivot = (index + 1) % projectOrder.size();
        if (pivot == 0) {
            return;
        }
        List<String> rotated = new ArrayList<>(projectOrder.size());
        rotated.addAll(projectOrder.subList(pivot, projectOrder.size()));
        rotated.addAll(projectOrder.subList(0, pivot));
        projectOrder.clear();
        projectOrder.addAll(rotated);
    }
}
