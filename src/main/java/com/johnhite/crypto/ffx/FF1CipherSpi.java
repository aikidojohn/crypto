package com.johnhite.crypto.ffx;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class FF1CipherSpi extends CipherSpi {
    private FFXAlgorithmParameterSpec paramSpec;
    private SecureRandom srand;
    private SecretKey key;
    private int mode;

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {
        System.out.print("mode: " + s);
    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {
        System.out.print("padding: " + s);
    }

    @Override
    protected int engineGetBlockSize() {
        System.out.print("blocksize: 128");
        return 128;
    }

    @Override
    protected int engineGetOutputSize(int i) {
        System.out.print("outputsize: " + i);
        return i;
    }

    @Override
    protected byte[] engineGetIV() {
        System.out.print("getIV: 0");
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int i, Key key, SecureRandom secureRandom) throws InvalidKeyException {

    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!key.getAlgorithm().equalsIgnoreCase("AES")) {
            throw new InvalidKeyException("AES Key expected for AES-FF1 Mode");
        }
        if (!(algorithmParameterSpec instanceof FFXAlgorithmParameterSpec)) {
            throw new InvalidAlgorithmParameterException("FFXAlgorithmParameterSpec required for AES-FF1 Mode");
        }
        this.key = (SecretKey) key;
        this.paramSpec = (FFXAlgorithmParameterSpec) algorithmParameterSpec;
        this.srand = secureRandom;
        this.mode = i;
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int i, int i1) {
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException {
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int i, int i1) throws IllegalBlockSizeException, BadPaddingException {
        if (mode == Cipher.ENCRYPT_MODE) {
            String output = encrypt(key, paramSpec.getTweak(), new String(bytes), paramSpec.getBase());
            return output.getBytes();
        } else if (mode == Cipher.DECRYPT_MODE) {
            String output = decrypt(key, paramSpec.getTweak(), new String(bytes), paramSpec.getBase());
            return output.getBytes();
        }
        else {
            throw new IllegalArgumentException("Invalid cipher mode. Only ENCRYPT_MODE and DECRYPT_MODE supported");
        }
    }

    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }

    private static final IvParameterSpec iv = new IvParameterSpec(new byte[16]);

    private static byte[] getBytes(byte[] source, int start, int length) {
        byte[] ret = new byte[length];
        int n = start + length > source.length ? source.length -1 : start + length -1;
        int ind = ret.length -1;
        for (int i= n; i >= start; i--) {
            ret[ind]= source[i];
            ind--;
        }
        return ret;
    }

    private static char[] getChars(char[] source, int start, int length, char pad) {
        char[] ret = new char[length];
        Arrays.fill(ret, pad);
        int n = start + length > source.length ? source.length -1 : start + length -1;
        int ind = ret.length -1;
        for (int i= n; i >= start; i--) {
            ret[ind]= source[i];
            ind--;
        }
        return ret;
    }

    public static boolean debug = false;
    public static String encrypt(SecretKey key, byte[] tweak, String value, RadixEncoding alphabet) {
        char[] X = value.toCharArray();
        int u = X.length/2;
        int v = X.length - u;
        int b = MoreMath.ceiling(MoreMath.ceiling((double)v * MoreMath.log(2, (double)alphabet.getRadix()))/8.0);
        int d = 4 * MoreMath.ceiling(b/4.0) + 4;

        char[] A = Arrays.copyOfRange(X, 0, u);
        char[] B = Arrays.copyOfRange(X, u, X.length);
        if (debug) {
            System.out.println("A = " + Arrays.toString(A));
            System.out.println("B = " + Arrays.toString(B));
        }

        ByteBuffer P = ByteBuffer.allocate(16);
        P.put(new byte[] {1,2,1,});
        //3 bytes of the radix
        P.put(ByteBuffer.allocate(4).putInt((int)alphabet.getRadix()).array(), 1, 3);
        P.put((byte)10);
        P.put((byte)(u%256));
        P.putInt(X.length);
        P.putInt(tweak.length);
        if (debug) {
            System.out.println("P = " + Arrays.toString(P.array()));
        }
        //This pads the length of the string to a multiple of 16
        int numZeros = (16 - ((b + tweak.length + 1) % 16)) % 16;

        byte[] Q0 = ByteBuffer.allocate(tweak.length + numZeros).put(tweak).array();
        for (int i=0; i < 10; i++) {
            byte[] Q2 = getBytes(numRadix(B, alphabet).toByteArray(), 0, b);
            ByteBuffer Q = ByteBuffer.allocate(Q0.length + Q2.length +1);
            Q.put(Q0);
            Q.put((byte)i);
            Q.put(Q2);
            if(debug) {
                System.out.println("Q = " + Arrays.toString(Q.array()));
            }

            byte[] R = prf(key, ByteBuffer.allocate(P.capacity() + Q.capacity()).put(P.array()).put(Q.array()).array());
            if (debug) {
                System.out.println("R= " + Arrays.toString(R));
            }
            ByteBuffer S = ByteBuffer.allocate(d);
            if (d < R.length) {
                S.put(Arrays.copyOfRange(R, 0, d));
            } else {
                S.put(R);
                for (int j = R.length; j < d; j += 16) {
                    byte[] pad = new byte[R.length];
                    Arrays.fill(pad, (byte) j);
                    byte[] mac = cipher(key, xor(R, pad, 0));
                    if (d - j < 16) {
                        S.put(Arrays.copyOfRange(mac, 0, (d - j)));
                    }
                    else {
                        S.put(mac);
                    }
                }
            }
            if (debug) {
                System.out.println("S = " + Hex.encode(S.array()));
            }
            BigInteger y = new BigInteger(1, S.array());
            if (debug) {
                System.out.println("y = " + y);
            }

            int m = i % 2 == 0 ? u : v;
            if (debug) {
                System.out.println("m = " + m);
            }
            BigInteger c = numRadix(A, alphabet).add(y).mod(BigInteger.valueOf(alphabet.getRadix()).pow(m));
            if (debug) {
                System.out.println("c = " + c);
            }
            char[] C = getChars(strRadix(c, alphabet), 0, m, alphabet.getChar(0));
            if (debug) {
                System.out.println("C = " + Arrays.toString(C));
            }
            A = B;
            B = C;
            if (debug) {
                System.out.println("A = " + Arrays.toString(A));
                System.out.println("B = " + Arrays.toString(B));
            }
        }
        //640 5. Return A || B.
        StringBuilder sb = new StringBuilder();
        sb.append(A);
        sb.append(B);
        return sb.toString();
    }

    public static String decrypt(SecretKey key, byte[] tweak, String value, RadixEncoding domain) {
        char[] X = value.toCharArray();
        int u = X.length/2;
        int v = X.length - u;
        int b = MoreMath.ceiling(MoreMath.ceiling((double)v * MoreMath.log(2, (double)domain.getRadix()))/8.0);
        int d = 4 * MoreMath.ceiling(b/4.0) + 4;

        char[] A = Arrays.copyOfRange(X, 0, u);
        char[] B = Arrays.copyOfRange(X, u, X.length);
        if (debug) {
            System.out.println("A = " + Arrays.toString(A));
            System.out.println("B = " + Arrays.toString(B));
        }

        ByteBuffer P = ByteBuffer.allocate(16);
        P.put(new byte[] {1,2,1,});
        //3 bytes of the radix
        P.put(ByteBuffer.allocate(4).putInt((int)domain.getRadix()).array(), 1, 3);
        P.put((byte)10);
        P.put((byte)(u%256));
        P.putInt(X.length);
        P.putInt(tweak.length);
        if (debug) {
            System.out.println("P = " + Arrays.toString(P.array()));
        }

        //This pads the length of the string to a multiple of 16
        int numZeros = (16 - ((b + tweak.length + 1) % 16)) % 16;

        byte[] Q0 = ByteBuffer.allocate(tweak.length + numZeros).put(tweak).array();
        for (int i=9; i >= 0; i--) {
            byte[] Q2 = getBytes(numRadix(A, domain).toByteArray(), 0, b);
            ByteBuffer Q = ByteBuffer.allocate(Q0.length + Q2.length +1);
            Q.put(Q0);
            Q.put((byte)i);
            Q.put(Q2);
            if (debug) {
                System.out.println("Q = " + Arrays.toString(Q.array()));
            }

            byte[] R = prf(key, ByteBuffer.allocate(P.capacity() + Q.capacity()).put(P.array()).put(Q.array()).array());
            if (debug) {
                System.out.println("R= " + Arrays.toString(R));
            }

            ByteBuffer S = ByteBuffer.allocate(d);
            if (d < R.length) {
                S.put(Arrays.copyOfRange(R, 0, d));
            } else {
                S.put(R);
                for (int j = R.length; j < d; j += 16) {
                    byte[] pad = new byte[R.length];
                    Arrays.fill(pad, (byte) j);
                    byte[] mac = cipher(key, xor(R, pad, 0));
                    if (d - j < 16) {
                        S.put(Arrays.copyOfRange(mac, 0, (d - j)));
                    }
                    else {
                        S.put(mac);
                    }
                }
            }
            if (debug) {
                System.out.println("S = " + Hex.encode(S.array()));
            }
            BigInteger y = new BigInteger(1, S.array());
            if (debug) {
                System.out.println("y = " + y);
            }

            int m = i % 2 == 0 ? u : v;
            if (debug) {
                System.out.println("m = " + m);
            }
            BigInteger c = numRadix(B, domain).subtract(y).mod(BigInteger.valueOf(domain.getRadix()).pow(m));
            char[] C = getChars(strRadix(c, domain), 0, m, domain.getChar(0));
            if (debug) {
                System.out.println("c = " + c);
                System.out.println("C = " + Arrays.toString(C));
            }
            B = A;
            A = C;
            if (debug) {
                System.out.println("A = " + Arrays.toString(A));
                System.out.println("B = " + Arrays.toString(B));
            }
        }
        //640 5. Return A || B.
        StringBuilder sb = new StringBuilder();
        sb.append(A);
        sb.append(B);
        return sb.toString();
    }

    public static int minlen(RadixEncoding alpha) {
        return MoreMath.logInt((int)alpha.getRadix(), 1000000, RoundingMode.CEILING);
    }
    public static long maxlen(RadixEncoding alpha) {
        return (long)(Math.pow(2.0, 32.0) - 1.0);
    }
    public static byte[] cipher(SecretKey key, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ciphertext = cipher.doFinal(data);
            return Arrays.copyOfRange(ciphertext, 0, 16);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] prf(SecretKey key, byte[] data) {
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

    private static byte[] xor(byte[] a, byte[] b, int bOffset) {
        byte[] c = new byte[a.length];
        for (int i=0; i < a.length; i++) {
            c[i] = (byte)(a[i] ^ b[i+bOffset]);
        }
        return c;
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

    private static BigInteger numRadix(char[] symbols, RadixEncoding domain) {
        BigInteger rad = BigInteger.valueOf(domain.getRadix());
        BigInteger x = BigInteger.valueOf(0);
        int pow = 0;
        for (int i=symbols.length-1; i >=0; i--) {
            x = x.add(rad.pow(pow).multiply(BigInteger.valueOf(domain.getIndex(symbols[i]))));
            pow++;
        }
        return x;
    }

    private static char[] strRadix(BigInteger n, RadixEncoding domain) {
        List<Character> chars = new ArrayList<>();
        BigInteger rad = BigInteger.valueOf(domain.getRadix());
        BigInteger val = n;
        while (val.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divAndRem = val.divideAndRemainder(rad);
            int ind = divAndRem[1].intValue();
            chars.add(domain.getChar(ind));
            val = divAndRem[0];
        }
        char[] result = new char[chars.size()];
        for (int i=0; i < chars.size(); i++) {
            result[i] = chars.get(i).charValue();
        }
        return reverseChar(result);
    }

    private static byte[] reverseBytes(byte[] x) {
        byte[] y = new byte[x.length];
        for (int i= 0; i < x.length; i++) {
            y[i] = x[x.length - 1 - i];
        }
        return y;
    }

    private static char[] reverseChar(char[] x) {
        char[] y = new char[x.length];
        for (int i= 0; i < x.length; i++) {
            y[i] = x[x.length - 1 - i];
        }
        return y;
    }


    public static void main(String... args) throws Exception {
        System.out.println(Arrays.toString(getBytes(new byte[]{10,47,5,10}, 0, 3)));
        BigInteger num = numRadix(new char[]{'1', '2', '0', '3', '7'}, RadixEncoders.NUMBER);
        System.out.println(num);
        System.out.println(Arrays.toString(num.toByteArray()));
        System.out.println("Range Number:    " + minlen(RadixEncoders.NUMBER) + " - " + maxlen(RadixEncoders.NUMBER));
        System.out.println("Range Email:     " + minlen(RadixEncoders.ASCII_EMAIL) + " - " + maxlen(RadixEncoders.ASCII_EMAIL));
        System.out.println("Range Printable: " + minlen(RadixEncoders.ASCII_PRINTABLE) + " - " + maxlen(RadixEncoders.ASCII_PRINTABLE));
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, random);
        SecretKey key = keyGen.generateKey();

        String message = "1234567890987654321";

        //String out = F_A10(message.length(), new byte[]{5, 19, -25}, 1, new BigInteger("11111111"), key);
        String enc = encrypt(key, new byte[]{5,19, -8, 28, 34,122,4}, message, RadixEncoders.NUMBER);
        System.out.println(enc);

        String dec = decrypt(key, new byte[]{5,19, -8, 28, 34,122,4}, enc, RadixEncoders.NUMBER);
        System.out.println(dec);

        message = "The quick brown fox jumps over the lazy dog!";
        enc = encrypt(key, new byte[]{5,19, -8, 28, 34,122,4}, message, RadixEncoders.ASCII_PRINTABLE);
        System.out.println(enc);

        dec = decrypt(key, new byte[]{5,19, -8, 28, 34,122,4}, enc, RadixEncoders.ASCII_PRINTABLE);
        System.out.println(dec);
    }

}
