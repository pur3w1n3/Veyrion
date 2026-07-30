package com.aq.jvmsentinel.ai.tool.datasource;

import com.fasterxml.jackson.databind.ObjectMapper;

/** 数据源共享 JSON 工具类。 */
public final class DatasourceJson {
    public static final ObjectMapper JSON = new ObjectMapper();

    private DatasourceJson() {
    }
}
