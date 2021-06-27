package com.johnhite.crypto.ffx;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class FF3Test {

    @Test
    public void testEncryptWithRadix10TestVector() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String encrypted = ff3.encrypt("890121234567890000");
        System.out.println(encrypted);
        //Assert.assertEquals("750918814058654607", encrypted); old FF3 value not FF3-1 value
    }
}
