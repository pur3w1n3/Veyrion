package com.aq.jvmsentinel.decompile;

/** Closed allowlist of decompilers executable only by an isolated Worker. */
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
