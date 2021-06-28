package com.johnhite.crypto.ffx;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Specified in NIST-SP 800-38Gr1
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
 *
 * Specific implementation of general FFX structure specified in
 * https://csrc.nist.gov/projects/block-cipher-techniques/bcm/modes-development
 * https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/proposed-modes/ffx/ffx-spec2.pdf
 *
 */
public class FF1 {
    private static final int METHOD_ALTERNATING_FEISTEL = 2;
    private static final int ADDITION_BLOCKWISE = 1;
    private static final int VERSION = 1;
    private static final IvParameterSpec iv = new IvParameterSpec(new byte[16]);
    private SecretKey key;
    private RadixEncoding base;
    private byte[] tweak;
    private Cipher aesCipher;
    private long minLength;
    private long maxLength;

    public void init(SecretKey key, FFXAlgorithmParameterSpec params) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (!key.getAlgorithm().equalsIgnoreCase("AES")) {
            throw new InvalidKeyException("AES-FF1 requires an AES key");
        }
        if (params.getBase().getRadix() < 2 || params.getBase().getRadix() > 65536) {
            throw new InvalidAlgorithmParameterException("Invalid radix encoding. AES-FF1 supports radix encodings in the range [2...65536]");
        }
        this.key = key;
        this.base =  params.getBase();
        this.tweak = params.getTweak() == null ? new byte[0] : params.getTweak();
        this.aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        this.minLength = minLen(this.base);
        this.maxLength = maxLen(this.base);
    }

    public String encrypt(String value) throws IllegalBlockSizeException, BadPaddingException {
        final char[] X = value.toCharArray();
        if (X.length < minLength || X.length > maxLength) {
            throw new IllegalBlockSizeException("Invalid message length. AES-FF1 for radix " + base.getRadix() + " supports message lengths " + minLength + " - " + maxLength);
        }
        if (!base.isValidEncoding(X)) {
            throw new IllegalArgumentException("Input is not a valid radix " + base.getRadix() + " encoding");
        }

        final int u = X.length/2;
        final int v = X.length - u;
        final int b = MoreMath.ceiling(MoreMath.ceiling((double)v * MoreMath.log(2, (double)base.getRadix()))/8.0);
        final int d = 4 * MoreMath.ceiling(b/4.0) + 4;

        final BigInteger radixBigInt = BigInteger.valueOf(base.getRadix());
        final BigInteger powRadixU = radixBigInt.pow(u);
        final BigInteger powRadixV = radixBigInt.pow(v);

        char[] A = Arrays.copyOfRange(X, 0, u);
        char[] B = Arrays.copyOfRange(X, u, X.length);

        //P is a fixed header for the PRF for each round
        final ByteBuffer P = ByteBuffer.allocate(16)
                .put(new byte[] {VERSION, METHOD_ALTERNATING_FEISTEL, ADDITION_BLOCKWISE})
                .put(intToBytes((int)base.getRadix()), 1, 3)
                .put((byte)10)
                .put((byte)(u%256)) //split(n)
                .putInt(X.length) //n
                .putInt(tweak.length); //t

        //This pads the length of the string to a multiple of 16
        final int numZeros = (16 - ((b + tweak.length + 1) % 16)) % 16;
        final byte[] Q0 = ByteBuffer.allocate(tweak.length + numZeros).put(tweak).array();

        for (int i=0; i < 10; i++) {
            final byte[] Q1 = getBytes(base.toBase10(B).toByteArray(), 0, b);
            //Q = T || [0]^numZeros || [i]^1 || [NUMradix(B)]^b
            final ByteBuffer Q = ByteBuffer.allocate(Q0.length + Q1.length +1)
                .put(Q0).put((byte)i).put(Q1);

            // R = PRF( P || Q )
            final byte[] R = prf(concat(P, Q).array());

            // S = first d bytes of R || CIPH(R xor [1]^16) || CIPH(R xor [2]^16) || ... || CIPH(R xor [d/16-1]^16)
            final ByteBuffer S = ByteBuffer.allocate(d).put(R, 0, Math.min(d, R.length));
            final byte[] pad = new byte[R.length];
            for (int j = R.length; j < d; j += 16) {
                Arrays.fill(pad, (byte) (j - R.length + 1));
                final byte[] mac = cipher(xor(pad, R));
                S.put(mac, 0, Math.min((d-j), mac.length));
            }

            final BigInteger y = new BigInteger(1, S.array());

            final int m = i % 2 == 0 ? u : v;
            final BigInteger radixPowM = i % 2 == 0 ? powRadixU : powRadixV;
            final BigInteger c = base.toBase10(A).add(y).mod(radixPowM);
            final char[] C = getChars(base.fromBase10(c), 0, m, base.getChar(0));

            A = B;
            B = C;
        }
        //640 5. Return A || B.
        StringBuilder sb = new StringBuilder();
        sb.append(A);
        sb.append(B);
        return sb.toString();
    }

    public String decrypt(String value) throws IllegalBlockSizeException, BadPaddingException {
        final char[] X = value.toCharArray();
        if (X.length < minLength || X.length > maxLength) {
            throw new IllegalBlockSizeException("Invalid message length. AES-FF1 for radix " + base.getRadix() + " supports message lengths " + minLength + " - " + maxLength);
        }
        if (!base.isValidEncoding(X)) {
            throw new IllegalArgumentException("Input is not a valid radix " + base.getRadix() + " encoding");
        }
        final int u = X.length/2;
        final int v = X.length - u;
        final int b = MoreMath.ceiling(MoreMath.ceiling((double)v * MoreMath.log(2, (double)base.getRadix()))/8.0);
        final int d = 4 * MoreMath.ceiling(b/4.0) + 4;

        final BigInteger radixBigInt = BigInteger.valueOf(base.getRadix());
        final BigInteger powRadixU = radixBigInt.pow(u);
        final BigInteger powRadixV = radixBigInt.pow(v);

        char[] A = Arrays.copyOfRange(X, 0, u);
        char[] B = Arrays.copyOfRange(X, u, X.length);

        //P is a fixed header for the PRF for each round
        final ByteBuffer P = ByteBuffer.allocate(16);
        P.put(new byte[] {VERSION, METHOD_ALTERNATING_FEISTEL, ADDITION_BLOCKWISE});
        P.put(intToBytes((int)base.getRadix()), 1, 3); //3 bytes of the radix
        P.put((byte)10);
        P.put((byte)(u%256));
        P.putInt(X.length);
        P.putInt(tweak.length);

        //This pads the length of the string to a multiple of 16
        final int numZeros = (16 - ((b + tweak.length + 1) % 16)) % 16;

        byte[] Q0 = ByteBuffer.allocate(tweak.length + numZeros).put(tweak).array();
        for (int i=9; i >= 0; i--) {
            byte[] Q1 = getBytes(base.toBase10(A).toByteArray(), 0, b);
            ByteBuffer Q = ByteBuffer.allocate(Q0.length + Q1.length +1);
            Q.put(Q0);
            Q.put((byte)i);
            Q.put(Q1);

            byte[] R = prf(concat(P, Q).array());

            // S = first d bytes of R || CIPH(R xor [1]^16) || CIPH(R xor [2]^16) || ... || CIPH(R xor [d/16-1]^16)
            ByteBuffer S = ByteBuffer.allocate(d);
            S.put(R, 0, Math.min(d, R.length));
            byte[] pad = new byte[R.length];
            for (int j = R.length; j < d; j += 16) {
                Arrays.fill(pad, (byte) (j - R.length + 1));
                byte[] mac = cipher(xor(pad, R));
                S.put(mac, 0, Math.min((d-j), mac.length));
            }

            BigInteger y = new BigInteger(1, S.array());

            int m = i % 2 == 0 ? u : v;
            final BigInteger radixPowM = i % 2 == 0 ? powRadixU : powRadixV;
            BigInteger c = base.toBase10(B).subtract(y).mod(radixPowM);
            char[] C = getChars(base.fromBase10(c), 0, m, base.getChar(0));
            B = A;
            A = C;
        }
        //640 5. Return A || B.
        StringBuilder sb = new StringBuilder();
        sb.append(A);
        sb.append(B);
        return sb.toString();
    }

    public byte[] cipher(byte[] data) throws BadPaddingException, IllegalBlockSizeException {
        return prf(data);
    }

    public byte[] prf(byte[] data) throws BadPaddingException, IllegalBlockSizeException {
        try {
            aesCipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] enc = aesCipher.doFinal(data);
            return Arrays.copyOfRange(enc, enc.length - 16, enc.length);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            //This should not be possible
            throw new SecurityException("Error initializing AES Cipher.");
        }
    }
    public static int minLen(RadixEncoding base) {
        return MoreMath.logInt((int)base.getRadix(), 1000000, RoundingMode.CEILING);
    }
    public static long maxLen(RadixEncoding base) {
        return (long)(Math.pow(2.0, 32.0) - 1.0);
    }

    /**
     * Blockwise XOR of byte arrays a and b storing the result in a;
     * @param a
     * @param b
     * @return
     */
    private static byte[] xor(byte[] a, byte[] b) {
        for (int i=0; i < a.length; i++) {
            a[i] ^= b[i];
        }
        return a;
    }

    /**
     * Returns an array of the specified length. If source is less than length,
     * the array will be have leading zeros to pad the length to the appropriate size.
     * @param source
     * @param start
     * @param length
     * @return
     */
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

    private static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    private static ByteBuffer concat(ByteBuffer a, ByteBuffer b) {
        return ByteBuffer.allocate(a.capacity() + b.capacity()).put(a.array()).put(b.array());
    }

    public static void main(String... args) throws Exception {

        System.out.println(Arrays.toString(getBytes(new byte[]{10,47,5,10}, 0, 3)));
        BigInteger num = RadixEncoders.BASE10.toBase10(new char[]{'1', '2', '0', '3', '7'});
        System.out.println(num);
        System.out.println(Arrays.toString(num.toByteArray()));
        System.out.println("Range Number:    " + minLen(RadixEncoders.BASE10) + " - " + maxLen(RadixEncoders.BASE10));
        System.out.println("Range Email:     " + minLen(RadixEncoders.ASCII_EMAIL) + " - " + maxLen(RadixEncoders.ASCII_EMAIL));
        System.out.println("Range Printable: " + minLen(RadixEncoders.ASCII_PRINTABLE) + " - " + maxLen(RadixEncoders.ASCII_PRINTABLE));
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, random);
        SecretKey key = keyGen.generateKey();

        String message = "1234567890987654321";

        FF1 ff1 = new FF1();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, new byte[]{5,19, -8, 28, 34,122,4});
        ff1.init(key, spec);
        String enc = ff1.encrypt(message);
        System.out.println(enc);

        String dec = ff1.decrypt(enc);
        System.out.println(dec);

        spec = new FFXAlgorithmParameterSpec(RadixEncoders.ASCII_PRINTABLE, new byte[]{5,19, -8, 28, 34,122,4});
        ff1.init(key, spec);
        message = "The quick brown fox jumps over the lazy dog!";
        enc = ff1.encrypt(message);
        System.out.println(enc);

        dec = ff1.decrypt(enc);
        System.out.println(dec);
    }
}
