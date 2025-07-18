package org.ndc.xmlsign;

import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class Signxmlsec {
    private final Path fileUploadPath = Paths.get(System.getProperty("user.dir"), "xmlsec-uploads");

    static {
        File nativeDir = new File(System.getProperty("user.home"), ".myapp/native");
        String osName = System.getProperty("os.name").toLowerCase();
        boolean isWindows = osName.contains("win");

        try {
            if(isWindows) {
                ResourceExtractor.LoadLibrary("libxml2.dll", nativeDir, isWindows);
                ResourceExtractor.LoadLibrary("libxmlsec.dll", nativeDir, isWindows);
                ResourceExtractor.LoadLibrary("libxmlsec-openssl.dll", nativeDir, isWindows);
                ResourceExtractor.LoadLibrary("signlibxmlsec.dll", nativeDir, isWindows);
            }else{
                ResourceExtractor.LoadLibrary("libsignlibxmlsec.so", nativeDir, isWindows);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Signxmlsec() throws IOException {
        if (!Files.exists(fileUploadPath)) {
            Files.createDirectories(fileUploadPath);
        }
    }

    private String convertBase64CertToPem(String base64Cert, String password) throws Exception {
        byte[] certBytes = Base64.getDecoder().decode(base64Cert);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        X509Certificate cert;
        try (InputStream in = new ByteArrayInputStream(certBytes)) {
            cert = (X509Certificate) factory.generateCertificate(in);
        } catch (Exception e1) {
            throw new Exception("Invalid certificate format or password.");
        }

        String base64CertContent = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64CertContent + "\n-----END CERTIFICATE-----";
    }

    public PrepareDataToSignOutput prepareDataToSign(PrepareDataToSignInput input) throws Exception {
        String key = UUID.randomUUID().toString() + "@" + input.nodePath;
        String encryptedKey = UrlSafeEncryption.encryptUrlSafe(key);
        String dataToSign = "Error";

        Path fileXmlPath = fileUploadPath.resolve(encryptedKey + "-file.xml");
        Path fileCertPath = fileUploadPath.resolve(encryptedKey + "-cert.pem");
        Path fileUnsignedPath = fileUploadPath.resolve(encryptedKey + "-unsigned.xml");

        try {
            Files.write(fileXmlPath, Base64.getDecoder().decode(input.fileXml));
            String certPem = convertBase64CertToPem(input.fileCertPem, null);
            Files.write(fileCertPath, certPem.getBytes());

            dataToSign = signlibxmlsec.prepareDataToSign(fileXmlPath.toString(), fileCertPath.toString(), fileUnsignedPath.toString(), input.nodePath);
        }
        catch (UnsatisfiedLinkError ex){
            System.out.println("ErrorPrepareDataToSign: " + ex.toString());
        }
        catch (Exception ex) {
            System.out.println("ErrorPrepareDataToSign: " + ex.toString());
        } finally {
            clearData(Arrays.asList(fileXmlPath, fileCertPath));
        }

        return new PrepareDataToSignOutput(encryptedKey, dataToSign);
    }

    public FinalizeSignatureOutput finalizeSignature(FinalizeSignatureInput input) {
        Path pathUnsigned = fileUploadPath.resolve(input.key + "-unsigned.xml");
        String file = "";

        try {
            if (!Files.exists(pathUnsigned)) {
                throw new FileNotFoundException("Unsigned file for key " + input.key + " not found.");
            }

            String decryptedKey = UrlSafeEncryption.decryptUrlSafe(input.key);
            String nodePath = decryptedKey.split("@")[1];
            Path fileSignedPath = fileUploadPath.resolve(input.key + "-signed.xml");

            signlibxmlsec.finalizeSignature(pathUnsigned.toString(), input.base64Signature, fileSignedPath.toString(), nodePath);
            byte[] signedBytes = Files.readAllBytes(fileSignedPath);
            file = Base64.getEncoder().encodeToString(signedBytes);

            Files.delete(fileSignedPath);
        } catch (Exception ex) {
            System.out.println("ErrorFinalizeSignature: " + ex.toString());
        } finally {
            clearData(Collections.singletonList(pathUnsigned));
        }

        return new FinalizeSignatureOutput(file);
    }

    public void clearAllData() throws IOException {
        if (Files.exists(fileUploadPath)) {
            Files.walk(fileUploadPath)
                    .sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            // Handle or log the error if needed
                        }
                    });
        }
        Files.createDirectories(fileUploadPath);
    }

    private void clearData(List<Path> files) {
        for (Path file : files) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException e) {
                // ignore
            }
        }
    }
}