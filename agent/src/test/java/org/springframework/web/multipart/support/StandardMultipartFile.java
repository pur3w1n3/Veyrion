package org.springframework.web.multipart.support;

import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;

/**
 * Stand-in for Spring's StandardMultipartHttpServletRequest$StandardMultipartFile.
 * Lives outside {@code com.aq.fixture} classPrefix so advice must observe transferTo
 * without relying on application call-site FileOutputStream hooks alone.
 */
public final class StandardMultipartFile implements MultipartFile {
    private final byte[] bytes;

    public StandardMultipartFile(byte[] bytes) {
        this.bytes = bytes == null ? new byte[0] : bytes.clone();
    }

    @Override
    public void transferTo(File dest) throws Exception {
        Files.write(dest.toPath(), bytes);
    }
}
