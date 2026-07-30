package com.aq.jvmsentinel.worker.docker;

import com.aq.jvmsentinel.analysis.experiment.GuardSurfaceCatalog;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 制品 JAR 内 MySQL Connector 检测与 FORCED Guard 白名单采集。
 */
public final class ArtifactJarInspection {
    private ArtifactJarInspection() { }

    /** 仅当 catalog JAR 内含 Connector/J 时选用协议级 MySQL。 */
    public static boolean containsMysqlConnector(Path artifact) {
        int entries = 0;
        try (ZipFile zip = new ZipFile(artifact.toFile())) {
            var iterator = zip.entries();
            while (iterator.hasMoreElements() && entries++ < 100_000) {
                ZipEntry entry = iterator.nextElement();
                if (entry.isDirectory()) continue;
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (name.contains("mysql-connector")
                        && (name.endsWith(".jar") || name.endsWith(".zip"))) return true;
            }
            return false;
        } catch (IOException ignored) {
            // 摘要/签名校验会在命令构建前拒绝畸形制品。
            return false;
        }
    }

    public static ExternalArtifactTaskExecutor.ForcedGuardAllowlist forcedGuardAllowlist(Path artifactPath) {
        GuardSurfaceCatalog.HarvestResult harvest = GuardSurfaceCatalog.harvestDetailed(artifactPath);
        GuardSurfaceCatalog.TypeNamesSelection selected =
                GuardSurfaceCatalog.typeNamesDetailed(harvest.surfaces());
        GuardSurfaceCatalog.TypeNamesProperty property =
                GuardSurfaceCatalog.formatTypeNamesPropertyDetailed(selected.names());
        boolean truncated = harvest.truncated() || selected.truncated() || property.truncated();
        String gap = truncated ? GuardSurfaceCatalog.GAP_CATALOG_TRUNCATED
                : (harvest.gapCode().isBlank() ? "" : harvest.gapCode());
        return new ExternalArtifactTaskExecutor.ForcedGuardAllowlist(property.csv(), truncated, gap);
    }
}
