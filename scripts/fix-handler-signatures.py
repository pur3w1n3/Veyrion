#!/usr/bin/env python3
import pathlib
import re

H = pathlib.Path(r"e:\ai\Veyrion\src\main\java\com\aq\jvmsentinel\control\http\ControlPlaneRouteHandlers.java")

def main():
    t = H.read_text(encoding="utf-8")
    fixes = [
        (r"ToolDataSource\.FactRecord ControlPlaneHttpSupport\.probeExecutionFailureFact\(",
         "ToolDataSource.FactRecord probeExecutionFailureFact("),
        (r"ToolDataSource\.FactRecord ControlPlaneHttpSupport\.probeFact\(",
         "ToolDataSource.FactRecord probeFact("),
        (r"static AiOutputLanguage ControlPlaneHttpSupport\.outputLanguage",
         "static AiOutputLanguage outputLanguage"),
        (r"static OperatorRole ControlPlaneHttpSupport\.operatorRole",
         "static OperatorRole operatorRole"),
    ]
    for a, b in fixes:
        t = re.sub(a, b, t)
    # 本地 wire 方法：调用改回同类
    local_static = [
        "auditRunMap", "probeExecutionFailureFact", "probeFact", "probeState",
        "outputLanguage", "operatorRole", "findingReplayMap", "entryFocusProbeMap",
        "sqlExperimentCardMap", "experimentPlanMap", "envelope", "artifactMap",
        "entryMap", "dependencyMap", "sinkMap", "evidenceMap", "findingMap",
        "hypothesisMaps", "pathStepMap", "pathMap", "pathRunMap", "scanMap",
        "dynamicTaskMap", "chainMap", "operatorMap", "providerMap", "inventoryMap",
        "roleBindingMap", "aiJobMap", "aiJobEventMap", "auditMap", "stringEnvelope",
        "uploadSessionMap", "readObjectOrEmpty", "requireCompletedRole", "dynamicBudgetForArtifact",
        "isActiveLifecycle", "probePlanHash", "persistedStringList", "hasExecutableMainClass",
        "isAuthGapFinding", "mergeProviderBundleIntoScan", "ensureProviderEvidence",
        "entryKey", "stripPrefix", "correlationIdFromPathRun", "prefixRefs", "simpleName",
        "sinkCategoryLabel", "sinkBindingKey", "entryBindingKey", "staticSinkSeverity",
        "sinkDeclaringClass",
    ]
    for name in local_static:
        t = t.replace(f"ControlPlaneHttpSupport.{name}(", f"{name}(")
    H.write_text(t, encoding="utf-8")
    print("patched handlers", len(t.splitlines()), "lines")

if __name__ == "__main__":
    main()
