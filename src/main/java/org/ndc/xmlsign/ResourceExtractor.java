package org.ndc.xmlsign;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

class ResourceExtractor {

    public static void LoadLibrary(String libFileName, File nativeDir, boolean isWindow) throws IOException {
        String subDir;
        if (isWindow) {
            subDir = "windows_64";
        } else {
            subDir = "linux_64";
        }

        String resourcePath = "/natives/" + subDir + "/" + libFileName;
        File nativeLib = extractOnce(resourcePath, nativeDir);

        System.load(nativeLib.getAbsolutePath());
    }

    public static File extractOnce(String resourcePath, File outputDir) throws IOException {
        if (!resourcePath.startsWith("/")) {
            resourcePath = "/" + resourcePath;
        }

        String fileName = Paths.get(resourcePath).getFileName().toString();
        File outputFile = new File(outputDir, fileName);

        if (!outputFile.exists()) {
            try (InputStream is = ResourceExtractor.class.getResourceAsStream(resourcePath)) {
                if (is == null) {
                    throw new FileNotFoundException("Resource not found: " + resourcePath);
                }

                // Ensure output directory exists
                outputDir.mkdirs();
                Files.copy(is, outputFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        }

        return outputFile;
    }
}
