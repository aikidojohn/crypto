package com.johnhite.crypto.ffx;

import org.bouncycastle.util.encoders.Hex;
import static org.junit.Assert.*;
import org.junit.Ignore;
import org.junit.Test;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Random;

public class FF1Test {
    @Test
    public void testEncryptWithRadix10TestVector() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER);
        ff1.init(key, spec);

        String encrypted = ff1.encrypt("0123456789");
        System.out.println(encrypted);
        assertEquals("2433477484", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVector() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER);
        ff1.init(key, spec);

        String encrypted = ff1.decrypt("2433477484");
        System.out.println(encrypted);
        assertEquals("0123456789", encrypted);
    }

    @Test
    public void testEncryptWithRadix10TestVectorAndTweak() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER, new byte[]{57, 56, 55, 54, 53, 52, 51, 50, 49, 48});
        ff1.init(key, spec);

        String encrypted = ff1.encrypt("0123456789");
        System.out.println(encrypted);
        assertEquals("6124200773", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVectorAndTweak() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER, new byte[]{57, 56, 55, 54, 53, 52, 51, 50, 49, 48});
        ff1.init(key, spec);

        String encrypted = ff1.decrypt("6124200773");
        System.out.println(encrypted);
        assertEquals("0123456789", encrypted);
    }

    @Test
    public void testEncryptWithRadix36TestVector() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        String encrypted = ff1.encrypt("0123456789abcdefghi");
        System.out.println(encrypted);
        assertEquals("a9tv40mll9kdu509eum", encrypted);
    }

    @Test
    public void testDecryptWithRadix36TestVector() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        String encrypted = ff1.decrypt("a9tv40mll9kdu509eum");
        System.out.println(encrypted);
        assertEquals("0123456789abcdefghi", encrypted);
    }

    @Test
    public void testEncryptWithLargeData() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        String encrypted = ff1.encrypt("0123456789abcdefghi0123456789abcdefghi0123456789abcdefghi0123456789abcdefghi");
        System.out.println(encrypted);
        assertEquals("jt7kfwms77q8j0qm9osehwdao5w45zeuduykbijo9ofwociihsmqao6p4asr27caddrqpn7huxi7", encrypted);
    }

    @Test
    public void testDecryptWithLargeData() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        String encrypted = ff1.decrypt("jt7kfwms77q8j0qm9osehwdao5w45zeuduykbijo9ofwociihsmqao6p4asr27caddrqpn7huxi7");
        System.out.println(encrypted);
        assertEquals("0123456789abcdefghi0123456789abcdefghi0123456789abcdefghi0123456789abcdefghi", encrypted);
    }

    @Test
    public void testEncryptMinLengthException() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        try {
            ff1.encrypt("012");
            fail("Expected IllegalBlockSizeException but no exception was thrown");
        } catch (IllegalBlockSizeException e) {
            assertEquals("Invalid message length. AES-FF1 for radix 36 supports message lengths 4 - 4294967295", e.getMessage());
        }
    }

    @Test
    public void testDecryptMinLengthException() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        try {
            ff1.decrypt("jt7");
            fail("Expected IllegalBlockSizeException but no exception was thrown");
        } catch (IllegalBlockSizeException e) {
            assertEquals("Invalid message length. AES-FF1 for radix 36 supports message lengths 4 - 4294967295", e.getMessage());
        }
    }

    @Test
    public void testEncryptEncodingMismatch() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        try {
            ff1.encrypt("abcdefg");
            fail("Expected IllegalArgumentException but no exception was thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("Input is not a valid radix 10 encoding", e.getMessage());
        }
    }

    @Test
    public void testDecryptEncodingMismatch() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        try {
            ff1.decrypt("abcdefg");
            fail("Expected IllegalArgumentException but no exception was thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("Input is not a valid radix 10 encoding", e.getMessage());
        }
    }

    @Ignore
    @Test
    public void testPerformance() throws Exception {
        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55});
        ff1.init(key, spec);

        Random rand = new Random();
        int radix = (int) RadixEncoders.BASE36.getRadix();
        List<String> values = new ArrayList<String>();
        for (int j = 0; j < 10000; j++) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 50; i++) {
                sb.append(RadixEncoders.BASE36.getChar(rand.nextInt(radix)));
            }
            values.add(sb.toString());
        }
        List<String> result = new ArrayList<>();
        long start = System.currentTimeMillis();
        for (int j = 0; j < 10000; j++) {
            result.add(ff1.encrypt(values.get(j)));
        }
        long end = System.currentTimeMillis();
        //System.out.println("Encrypt Performance: " + (end - start) + "ms");

        result = new ArrayList<>();
        start = System.currentTimeMillis();
        for (int j = 0; j < 10000; j++) {
            result.add(ff1.encrypt(values.get(j)));
        }
        end = System.currentTimeMillis();
        System.out.println("Encrypt Performance: " + (end - start) + "ms");

        List<String> result2 = new ArrayList<>();
        start = System.currentTimeMillis();
        for (int j = 0; j < 10000; j++) {
            result2.add(ff1.decrypt(result.get(j)));
        }
        end = System.currentTimeMillis();
        System.out.println("Decrypt Performance: " + (end - start) + "ms");
    }

}
