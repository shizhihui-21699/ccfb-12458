package com.example.portal;
import java.security.Signature;
import java.security.KeyPairGenerator;

public class SsoToken {
    public static Signature rs256() throws Exception {
        // RSASSA-PKCS1-v1_5 + SHA-256：经典安全，PQ 风险在 RSA 本身
        return Signature.getInstance("SHA256withRSA");
    }
    public static KeyPairGenerator rsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg;
    }
}
