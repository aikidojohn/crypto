package com.johnhite.crypto.ffx;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;

/**
 * Adaptation of FF3 Test Vectors for FF3-1
 */
public class FF3v1Test {

    @Test
    public void testEncryptWithRadix10TestVector1() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String encrypted = ff3.encrypt("890121234567890000");
        System.out.println(encrypted);
        assertEquals("477064185124354662", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVector1() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String plaintext = ff3.decrypt("477064185124354662");
        System.out.println(plaintext);
        assertEquals("890121234567890000", plaintext);
    }

    @Test
    public void testEncryptWithRadix10TestVector2() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("9A768A92F60E12D8"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String encrypted = ff3.encrypt("890121234567890000");
        System.out.println(encrypted);
        assertEquals("654751978780866243", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVector2() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("9A768A92F60E12D8"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String plaintext = ff3.decrypt("654751978780866243");
        System.out.println(plaintext);
        assertEquals("890121234567890000", plaintext);
    }

    @Test
    public void testEncryptWithRadix10TestVector3() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String encrypted = ff3.encrypt("89012123456789000000789000000");
        System.out.println(encrypted);
        assertEquals("40726117733246590818927285071", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVector3() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String plaintext = ff3.decrypt("40726117733246590818927285071");
        System.out.println(plaintext);
        assertEquals("89012123456789000000789000000", plaintext);
    }

    @Test
    public void testEncryptWithRadix10TestVector4() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("0000000000000000"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String encrypted = ff3.encrypt("89012123456789000000789000000");
        System.out.println(encrypted);
        assertEquals("34695224821734535122613701434", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVector4() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A94");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("0000000000000000"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String plaintext = ff3.decrypt("34695224821734535122613701434");
        System.out.println(plaintext);
        assertEquals("89012123456789000000789000000", plaintext);
    }

    // AES-192
    @Test
    public void testEncryptWithRadix10TestVector6() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String encrypted = ff3.encrypt("890121234567890000");
        System.out.println(encrypted);
        assertEquals("428521014080513180", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVector6() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String plaintext = ff3.decrypt("428521014080513180");
        System.out.println(plaintext);
        assertEquals("890121234567890000", plaintext);
    }

    //AES 256
    @Test
    public void testEncryptWithRadix10TestVector11() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String encrypted = ff3.encrypt("890121234567890000");
        System.out.println(encrypted);
        assertEquals("739867966748611431", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVector11() throws Exception {

        byte[] keyBytes = Hex.decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, Hex.decode("D8E7920AFA330A73"));
        FF3v1 ff3 = new FF3v1();
        ff3.init(key, params);
        String plaintext = ff3.decrypt("739867966748611431");
        System.out.println(plaintext);
        assertEquals("890121234567890000", plaintext);
    }
}
