package com.example.pay;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class PaymentCipher {
    public static String digest(String input) throws Exception {
        // 写法 4：Java JCE 的 MD5
        MessageDigest md = MessageDigest.getInstance("MD5");
        return HexFormat.of().formatHex(md.digest(input.getBytes()));
    }

    public static byte[] desEncrypt(byte[] key, byte[] data) throws Exception {
        // Java 变换串：DESede/ECB
        Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"));
        return c.doFinal(data);
    }

    public static String weakToken() {
        Random r = new Random();   // java.util.Random 用于安全令牌
        return "tok-" + r.nextInt();
    }

    public static byte[] rsaWrap(byte[] kek, java.security.PublicKey pub) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.WRAP_MODE, pub);
        return c.wrap(new SecretKeySpec(kek, "AES"));
    }
}
