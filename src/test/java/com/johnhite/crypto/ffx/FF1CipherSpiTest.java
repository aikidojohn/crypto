package com.johnhite.crypto.ffx;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
 */
public class FF1CipherSpiTest {

    @Test
    public void testEncryptWithRadix10TestVector() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER);
        FF1CipherSpi cipher = new FF1CipherSpi();
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, params, new SecureRandom());
        byte[] outputBytes = cipher.engineDoFinal("0123456789".getBytes(StandardCharsets.UTF_8), 0, 0);
        String encrypted = new String(outputBytes);
        System.out.println(encrypted);
        Assert.assertEquals("2433477484", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVector() throws Exception {

        /*byte[] keyBytes = DatatypeConverter.parseHexBinary("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        String encrypted = FF1Encryption.decrypt(key, new byte[]{}, "2433477484", Alpha.NUMBER );
        System.out.println(encrypted);
        Assert.assertEquals("0123456789", encrypted);*/

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER);
        FF1CipherSpi cipher = new FF1CipherSpi();
        cipher.engineInit(Cipher.DECRYPT_MODE, key, params, new SecureRandom());
        byte[] outputBytes = cipher.engineDoFinal("2433477484".getBytes(StandardCharsets.UTF_8), 0, 0);
        //String encrypted = FF1Encryption.encrypt(key, new byte[]{}, "0123456789", Alpha.NUMBER );
        String decrypted = new String(outputBytes);
        System.out.println(decrypted);
        Assert.assertEquals("0123456789", decrypted);
    }

    @Test
    public void testEncryptWithRadix10TestVectorAndTweak() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
       /* String encrypted = FF1Encryption.encrypt(key, new byte[]{57, 56, 55, 54, 53, 52, 51, 50, 49, 48}, "0123456789", Alpha.NUMBER );
        System.out.println(encrypted);
        Assert.assertEquals("6124200773", encrypted);*/
        byte[] tweak = new byte[]{57, 56, 55, 54, 53, 52, 51, 50, 49, 48};
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER, tweak);
        FF1CipherSpi cipher = new FF1CipherSpi();
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, params, new SecureRandom());
        byte[] outputBytes = cipher.engineDoFinal("0123456789".getBytes(StandardCharsets.UTF_8), 0, 0);
        String encrypted = new String(outputBytes);
        System.out.println(encrypted);
        Assert.assertEquals("6124200773", encrypted);
    }

    @Test
    public void testDecryptWithRadix10TestVectorAndTweak() throws Exception{

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        /*String encrypted = FF1Encryption.decrypt(key, new byte[]{57, 56, 55, 54, 53, 52, 51, 50, 49, 48}, "6124200773", Alpha.NUMBER );
        System.out.println(encrypted);
        Assert.assertEquals("0123456789", encrypted);*/
        byte[] tweak = new byte[]{57, 56, 55, 54, 53, 52, 51, 50, 49, 48};
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.NUMBER, tweak);
        FF1CipherSpi cipher = new FF1CipherSpi();
        cipher.engineInit(Cipher.DECRYPT_MODE, key, params, new SecureRandom());
        byte[] outputBytes = cipher.engineDoFinal("6124200773".getBytes(StandardCharsets.UTF_8), 0, 0);
        //String encrypted = FF1Encryption.encrypt(key, new byte[]{}, "0123456789", Alpha.NUMBER );
        String decrypted = new String(outputBytes);
        System.out.println(decrypted);
        Assert.assertEquals("0123456789", decrypted);
    }

    @Test
    public void testEncryptWithRadix36TestVector() throws Exception{

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        byte[] tweak = new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55};
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, tweak);
        /*String encrypted = FF1Encryption.encrypt(key, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55}, "0123456789abcdefghi", Alpha.BASE36 );
        System.out.println(encrypted);
        Assert.assertEquals("a9tv40mll9kdu509eum", encrypted);*/
        FF1CipherSpi cipher = new FF1CipherSpi();
        cipher.engineInit(Cipher.ENCRYPT_MODE, key, params, new SecureRandom());
        byte[] outputBytes = cipher.engineDoFinal("0123456789abcdefghi".getBytes(StandardCharsets.UTF_8), 0, 0);
        String encrypted = new String(outputBytes);
        System.out.println(encrypted);
        Assert.assertEquals("a9tv40mll9kdu509eum", encrypted);

    }

    @Test
    public void testDecryptWithRadix36TestVector() throws Exception {

        byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        byte[] tweak = new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55};
        FFXAlgorithmParameterSpec params = new FFXAlgorithmParameterSpec(RadixEncoders.BASE36, tweak);
        /*String encrypted = FF1Encryption.decrypt(key, new byte[]{55, 55, 55, 55, 112, 113, 114, 115, 55, 55, 55}, "a9tv40mll9kdu509eum", Alpha.BASE36 );
        System.out.println(encrypted);
        Assert.assertEquals("0123456789abcdefghi", encrypted);*/

        FF1CipherSpi cipher = new FF1CipherSpi();
        cipher.engineInit(Cipher.DECRYPT_MODE, key, params, new SecureRandom());
        byte[] outputBytes = cipher.engineDoFinal("a9tv40mll9kdu509eum".getBytes(StandardCharsets.UTF_8), 0, 0);
        //String encrypted = FF1Encryption.encrypt(key, new byte[]{}, "0123456789", Alpha.NUMBER );
        String decrypted = new String(outputBytes);
        System.out.println(decrypted);
        Assert.assertEquals("0123456789abcdefghi", decrypted);
    }
}
