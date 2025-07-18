package org.ndc.xmlsign;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

class UrlSafeEncryption {
    private static final byte[] KEY = "1234567890123456".getBytes(StandardCharsets.UTF_8);
    private static final byte[] IV = "6543210987654321".getBytes(StandardCharsets.UTF_8);

    public static String encryptUrlSafe(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return toBase64Url(encrypted);
    }

    public static String decryptUrlSafe(String base64Url) throws Exception {
        byte[] encrypted = fromBase64Url(base64Url);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static String toBase64Url(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes)
                .replace('+', '-')
                .replace('/', '_')
                .replaceAll("=+$", "");
    }

    private static byte[] fromBase64Url(String base64Url) {
        String padded = base64Url
                .replace('-', '+')
                .replace('_', '/');

        int padding = 4 - padded.length() % 4;
        if (padding < 4) padded += "=".repeat(padding);

        return Base64.getDecoder().decode(padded);
    }
}
