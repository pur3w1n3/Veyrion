package com.aq.jvmsentinel.control.store;

import com.aq.jvmsentinel.control.ControlPlaneStore;

/** Store 辅助接口。 */
public interface ControlPlaneEntityAccess {
    public ControlPlaneStore.ProjectRecord requireProject(String projectId);

    public ControlPlaneStore.ProjectRecord project(String projectId);

    public ControlPlaneStore.ScanRecord requireScan(String scanId);

    public ControlPlaneStore.ScanRecord scan(String scanId);
}
