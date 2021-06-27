package com.johnhite.crypto.ffx;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

public abstract class FFXBase {
    private static final IvParameterSpec iv = new IvParameterSpec(new byte[16]);
    protected SecretKey key;
    protected FFXAlgorithmParameterSpec spec;

    public abstract void init(SecretKey key, FFXAlgorithmParameterSpec spec);

    protected final byte[] cipher(SecretKey key, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ciphertext = cipher.doFinal(data);
            return Arrays.copyOfRange(ciphertext, 0, 16);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected final byte[] prf(SecretKey key, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            int m = data.length / 16;
            byte[] y = new byte[16];
            for (int i=0; i < m; i++) {
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                y = Arrays.copyOfRange(cipher.doFinal(xor(y, data, i*16)), 0 , 16);
            }
            return y;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected final byte[] xor(byte[] a, byte[] b, int bOffset) {
        byte[] c = new byte[a.length];
        for (int i=0; i < a.length; i++) {
            c[i] = (byte)(a[i] ^ b[i+bOffset]);
        }
        return c;
    }

    protected final byte[] reverse(byte[] x) {
        byte[] y = new byte[x.length];
        for (int i= 0; i < x.length; i++) {
            y[i] = x[x.length - 1 - i];
        }
        return y;
    }

    protected final char[] reverse(char[] x) {
        char[] y = new char[x.length];
        for (int i= 0; i < x.length; i++) {
            y[i] = x[x.length - 1 - i];
        }
        return y;
    }
}
