package org.springframework.web.multipart;

import java.io.File;
import java.nio.file.Path;

/** Minimal Spring MultipartFile surface for agent acceptance fixtures. */
public interface MultipartFile {
    void transferTo(File dest) throws Exception;

    default void transferTo(Path dest) throws Exception {
        transferTo(dest.toFile());
    }
}
