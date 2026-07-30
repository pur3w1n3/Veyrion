package com.aq.jvmsentinel.decompile;

/** 仅可由隔离 Worker 执行的 decompiler 封闭 allowlist。 */
public enum DecompilerTool {
    VINEFLOWER("org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler"),
    CFR("org.benf.cfr.reader.Main");

    private final String mainClass;

    DecompilerTool(String mainClass) {
        this.mainClass = mainClass;
    }

    public String mainClass() {
        return mainClass;
    }
}
