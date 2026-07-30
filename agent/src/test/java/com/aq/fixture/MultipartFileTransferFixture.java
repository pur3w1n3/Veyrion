package com.aq.fixture;

import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.support.StandardMultipartFile;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Mirrors kvf {@code FileUploadKit#upload} → {@code MultipartFile#transferTo}.
 */
public final class MultipartFileTransferFixture {
    private MultipartFileTransferFixture() {
    }

    public static void main(String[] args) throws Exception {
        Path outDir = Path.of(System.getProperty("veyrion.fixture.output", "fixture-output.txt"))
                .toAbsolutePath().getParent();
        if (outDir == null) {
            outDir = Path.of(".").toAbsolutePath();
        }
        Files.createDirectories(outDir);
        File dest = outDir.resolve("upload-dest.bin").toFile();
        MultipartFile file = new StandardMultipartFile("synthetic-upload-v1".getBytes(StandardCharsets.UTF_8));
        new FileUploadKit().upload(file, dest);
        if (!dest.isFile() || dest.length() == 0) {
            throw new IllegalStateException("transferTo did not write destination");
        }
        System.out.println("MultipartFileTransferFixture: PASS");
    }

    /** Application call site under classPrefix (like kvf FileUploadKit). */
    public static final class FileUploadKit {
        public void upload(MultipartFile file, File dest) throws Exception {
            file.transferTo(dest);
        }
    }
}
