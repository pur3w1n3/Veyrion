package com.aq.jvmsentinel.analysis.kernel;

import java.util.Locale;
import java.util.Optional;

/** Tiny primitive effect table for MethodSummary seeding (not a full sink catalog). */
public final class PrimitiveEffectCatalog {
    private PrimitiveEffectCatalog() {
    }

    public static Optional<String> match(String owner, String name) {
        String o = owner == null ? "" : owner.replace('/', '.');
        String n = name == null ? "" : name;
        String lowerName = n.toLowerCase(Locale.ROOT);
        String lowerOwner = o.toLowerCase(Locale.ROOT);

        if (o.equals("java.lang.Runtime") && n.equals("exec")) {
            return Optional.of("EFFECT:COMMAND");
        }
        if (o.equals("java.lang.ProcessBuilder") && (n.equals("start") || n.equals("command"))) {
            return Optional.of("EFFECT:COMMAND");
        }
        if ((o.equals("java.sql.Statement") || o.equals("java.sql.PreparedStatement")
                || o.equals("java.sql.Connection") || lowerOwner.contains("jdbc")
                || lowerOwner.endsWith(".statement"))
                && (n.equals("execute") || n.equals("executeQuery") || n.equals("executeUpdate")
                || n.equals("executeLargeUpdate") || n.equals("prepareStatement"))) {
            return Optional.of("EFFECT:SQL");
        }
        if (o.equals("java.lang.Runtime") && (n.equals("load") || n.equals("loadLibrary"))) {
            return Optional.of("EFFECT:NATIVE_CODE");
        }
        if ((o.equals("javax.naming.InitialContext") || o.equals("javax.naming.Context")
                || o.equals("javax.naming.directory.InitialDirContext"))
                && n.equals("lookup")) {
            return Optional.of("EFFECT:JNDI");
        }
        if (o.equals("java.lang.Class") && (n.equals("forName") || n.equals("newInstance"))) {
            return Optional.of("EFFECT:CLASS_LOADING");
        }
        if ((o.equals("java.io.ObjectInputStream") || lowerOwner.contains("objectinput"))
                && (n.equals("readObject") || n.equals("readUnshared"))) {
            return Optional.of("EFFECT:DESERIALIZATION");
        }
        if ((o.equals("javax.script.ScriptEngine") || lowerOwner.contains("scriptengine"))
                && (n.equals("eval") || n.equals("compile"))) {
            return Optional.of("EFFECT:SCRIPT");
        }
        if (lowerName.equals("exec") && lowerOwner.contains("runtime")) {
            return Optional.of("EFFECT:COMMAND");
        }
        // Conservative name heuristics for app wrappers that look like sinks.
        if (lowerName.contains("executequery") || lowerName.contains("rawsql")
                || lowerName.equals("query") && lowerOwner.contains("sql")) {
            return Optional.of("EFFECT:SQL");
        }
        if (lowerName.contains("runcmd") || lowerName.contains("shellexec")
                || lowerName.equals("system") && lowerOwner.contains("process")) {
            return Optional.of("EFFECT:COMMAND");
        }
        return Optional.empty();
    }
}
