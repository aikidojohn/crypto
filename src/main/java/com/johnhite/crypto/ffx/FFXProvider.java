package com.johnhite.crypto.ffx;

import javax.crypto.*;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class FFXProvider extends Provider {
    public FFXProvider() {
        super("FFX", "0.0.1", "Crypto Provider implementing NIST SP 800-58G (Draft1) Format Preserving Encryption");
        put("Cipher.AES/FF1/NoPadding", "com.johnhite.crypto.ffx.FF1CipherSpi");
    }

    public static void main(String... args) throws Exception {
        //Security.addProvider(new FFXProvider());
        FFXProvider p = new FFXProvider();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, new SecureRandom());
        SecretKey key = keyGen.generateKey();
        FFXAlgorithmParameterSpec ffxParamSpec = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER, "user1".getBytes(StandardCharsets.UTF_8));
        FF1CipherSpi c = (FF1CipherSpi) p.getCipherSpi("AES/FF1/NoPadding");
        c.engineInit(Cipher.ENCRYPT_MODE, key, ffxParamSpec, new SecureRandom());
        byte[] output = c.engineDoFinal("0123456789".getBytes(StandardCharsets.UTF_8), 0, 0);
        System.out.println("Input: 0123456789");
        System.out.println("Encrypted: " + new String(output));

        c.engineInit(Cipher.DECRYPT_MODE, key, ffxParamSpec, new SecureRandom());
        output = c.engineDoFinal(output, 0, 0);
        System.out.println("Decrypted: " + new String(output));
    }

    public CipherSpi getCipherSpi(String transform) throws NoSuchAlgorithmException {

        Provider.Service s = this.getService("Cipher", transform);
        CipherSpi spi = (CipherSpi)s.newInstance((Object)null);
        return spi;
    }
}
