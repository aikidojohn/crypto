package com.johnhite.crypto.ffx;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/ffx/ffx-spec2.pdf
 * FF1 and FF3 are based on this pattern
 */
public class FFX {
    private static final IvParameterSpec iv = new IvParameterSpec(new byte[16]);
    private static final BigInteger BILLION = BigInteger.valueOf(1000000000);

    public static String encrypt(SecretKey key, byte[] tweak, String value) {
        int n = value.length();
        int r = rnds(n);
        int l = n/2;
        BigInteger A = new BigInteger(value.substring(0, l));
        BigInteger B = new BigInteger(value.substring(l, n));
        for (int i =0; i < r; i++) {
            BigInteger F = F_A10(n, tweak, i, B, key);
            //System.out.println("Round: n = " + n + ", i = " + i + ", B = " + B + ", F = " + F);
            int m = (i % 2 == 0) ? l: n - l;
            BigInteger C = addBlockwise(A, F, m, 10);
            //System.out.println("round " + i + ": A = " + A + ", B = " + B + ", C = " + C + ", F = "+ F);
            A = B;
            B = C;
        }
        return num10(A, l) + num10(B, n-l);
    }

    public static String decrypt(SecretKey key, byte[] tweak, String value) {
        int n = value.length();
        int r = rnds(n);
        int l = n/2;
        BigInteger A = new BigInteger(value.substring(0, l));
        BigInteger B = new BigInteger(value.substring(l, n));
        for (int i =r-1; i >= 0; i--) {
            BigInteger C = B;
            B = A;
            BigInteger F = F_A10(n, tweak, i, B, key);
            //System.out.println("Round: n = " + n + ", i = " + i + ", B = " + B + ", F = " + F);
            int m = (i % 2 == 0) ? l: n - l;
            A = subBlockwise(C, F, m, 10);
            //System.out.println("round " + i + ": A = " + A + ", B = " + B + ", C = " + C + ", F = "+ F);
        }
        return num10(A, l) + num10(B, n-l);
    }

    private static BigInteger F_A10(int messageLen, byte[] tweak, int round, BigInteger messageB, SecretKey key) {
        //P
        int t = tweak.length;
        int padLen = (t+9)%16; //ensure multiple of 16 bytes
        ByteBuffer q = ByteBuffer.allocate(t + 9 + padLen);
        q.put(tweak)
                .put(new byte[padLen])
                .put((byte)round)
                .put(messageB.toByteArray());
        byte[] y = cbcmac(key, q.array());
        BigInteger yp = new BigInteger(1, Arrays.copyOfRange(y,0,8));
        BigInteger ypp = new BigInteger(1, Arrays.copyOfRange(y, 8, 16));
        int m = (round % 2 == 0) ? messageLen / 2 : messageLen - messageLen/2;
        BigInteger z = (m <= 9 ) ?
                ypp.mod(BigInteger.TEN.pow(m)) :
                yp.mod(BigInteger.TEN.pow(m - 9)).multiply(BILLION).add(ypp.mod(BILLION));
        return z;
    }

    private static BigInteger addBlockwise(BigInteger a, BigInteger b, int l, int radix) {
        return a.add(b).mod(BigInteger.valueOf(radix).pow(l));
    }

    private static BigInteger subBlockwise(BigInteger a, BigInteger b, int l, int radix) {
        BigInteger mod = BigInteger.valueOf(radix).pow(l);
        BigInteger tmp = a.subtract(b).mod(mod);
        return tmp;
    }

    private static int rnds(int n) {
        if (n >= 10) return 12;
        if (n >= 6) return 18;
        return 24;
    }

    //rough cbc-mac
    private static byte[] cbcmac(SecretKey key, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            cipher.update(ByteBuffer.allocate(4).putInt(data.length).array());
            byte[] ciphertext = cipher.doFinal(data);
            return Arrays.copyOfRange(ciphertext, ciphertext.length -16, ciphertext.length);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String num10(BigInteger num, int len) {
        String n = num.toString();
        StringBuilder sb = new StringBuilder();
        for (int i= 0; i < len - n.length(); i++) {
            sb.append('0');
        }
        sb.append(n);
        return sb.toString();
    }

    public static void main(String... args) throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, random);
        SecretKey key = keyGen.generateKey();

        String message = "4111111111111111223";
        //String out = F_A10(message.length(), new byte[]{5, 19, -25}, 1, new BigInteger("11111111"), key);
        String enc = encrypt(key, new byte[]{5,19, -8}, message);
        System.out.println(enc);

        String dec = decrypt(key, new byte[]{5,19, -8}, enc);
        System.out.println(dec);
    }
}
