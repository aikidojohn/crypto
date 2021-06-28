package com.johnhite.crypto.ffx;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
 * @deprecated FF3 implementation provided for compatibility with other implementations. FF3-1 should be used instead as it addresses security flaws found in FF3.
 */
@Deprecated
public class FF3 {
    private static final IvParameterSpec iv = new IvParameterSpec(new byte[16]);
    private SecretKey key;
    private RadixEncoding base;
    private byte[] tweak;
    private long minLength;
    private long maxLength;
    public static boolean debug = false;

    public void init(SecretKey key, FFXAlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (spec.getTweak() == null || spec.getTweak().length != 8) {
            throw new InvalidAlgorithmParameterException("AES-FF3 requires a 64 bit tweak value");
        }
        if (!key.getAlgorithm().equalsIgnoreCase("AES")) {
            throw new InvalidKeyException("AES-FF3 requires an AES Key");
        }
        this.key = new SecretKeySpec(reverse(key.getEncoded()), "AES");
        this.base = spec.getBase();
        this.tweak = spec.getTweak();
        this.minLength = minlen(this.base);
        this.maxLength = maxlen(this.base);
    }

    public String encrypt(String value) throws IllegalBlockSizeException {
        char[] X = value.toCharArray();
        if (X.length < minLength || X.length > maxLength) {
            throw new IllegalBlockSizeException("Invalid message length. AES-FF3 for radix " + base.getRadix() + " supports message lengths " + minLength + " - " + maxLength);
        }
        if (!base.isValidEncoding(X)) {
            throw new IllegalArgumentException("Input is not a valid radix " + base.getRadix() + " encoding");
        }
        int v = X.length/2;
        int u = X.length - v;
        //Let A = X[1..u]; B = X[u + 1..n]
        char[] A = reverse(Arrays.copyOfRange(X, 0, u));
        char[] B = reverse(Arrays.copyOfRange(X, u, X.length));
        if (debug) {
            System.out.println(new String(A) + " " + new String(B));
        }

        //Let TL = T[0..27] || [0000] and TR = T[32..55] || T[28..31] || [0000]
        ByteBuffer TL = ByteBuffer.allocate(4);
        TL.put(tweak,0,4);
        ByteBuffer TR = ByteBuffer.allocate(4);
        TR.put(tweak, 4,4);
        if (debug) {
            System.out.println("TL = " + Arrays.toString(TL.array()) + " - " + Hex.toHexString(TL.array()));
            System.out.println("TR = " + Arrays.toString(TR.array()) + " - " + Hex.toHexString(TR.array()));
        }
        //631 4. For i from 0 to 7:
        for (int i=0; i < 8; i++) {
            //632 i. If i is even, let m = u and W = TR, else let m = v and W = TL.
            int m =0;
            ByteBuffer W;
            if (i %2 == 0) {
                m = u;
                W = TR;
            } else {
                m = v;
                W = TL;
            }
            if (debug) {
                System.out.println("m = " + m);
                System.out.println("W = " + Hex.toHexString(W.array()));
            }
            //        ii. Let P = W ⊕ [i]
            //4 || [NUMradix (REV(B))]12 633 .
            ByteBuffer P = ByteBuffer.allocate(16);
            P.putInt(W.getInt(0) ^ i);
            BigInteger numRad = base.toBase10(B); //fromRadix(B, base);
            P.put(getBytes(numRad.toByteArray(),0,12));
            if (debug) {
                System.out.println(" P = " + Arrays.toString(P.array()));
            }

            //634 iii Let S = REVB(CIPHREVB(K)REVB(P)).
            byte[] S = reverse(cipher(reverse(P.array())));
            if (debug) {
                System.out.println("S = " + Arrays.toString(S) + " - " + Hex.toHexString(S));
            }
            //635 iv. Let y = NUM(S).
            BigInteger y = new BigInteger(1, S);

            //        v. Let c = (NUMradix (REV(A)) + y) mod radix m 636 .
            BigInteger c = (base.toBase10(A).add(y)).mod(BigInteger.valueOf(base.getRadix()).pow(m));
            //System.out.println("y = " + y + ", c = " + c);
            //        vi. Let C = REV(STRm 637 radix (c)).
            char[] C = getChars(base.fromBase10(c), 0, m, base.getChar(0));
            if (debug) {
                System.out.println("y = " + y.toString());
                System.out.println("C = " + c.toString());
                System.out.println("c = " + new String(C));
            }
            A = B;
            B = C;
            //638 vii. Let A = B.
            //639 viii. Let B = C.
        }
        //640 5. Return A || B.
        StringBuilder sb = new StringBuilder();
        sb.append(reverse(A));
        sb.append(reverse(B));
        return sb.toString();
    }

    public String decrypt(String value) throws IllegalBlockSizeException {
        //681 1. Let u = ⌈n/2⌉; v = n – u.
        char[] X = value.toCharArray();
        if (X.length < minLength || X.length > maxLength) {
            throw new IllegalBlockSizeException("Invalid message length. AES-FF3 for radix " + base.getRadix() + " supports message lengths " + minLength + " - " + maxLength);
        }
        if (!base.isValidEncoding(X)) {
            throw new IllegalArgumentException("Input is not a valid radix " + base.getRadix() + " encoding");
        }
        int v = X.length/2;
        int u = X.length - v;

        //682 2. Let A = X[1..u]; B = X[u + 1..n].
        char[] A = reverse(Arrays.copyOfRange(X, 0, u));
        char[] B = reverse(Arrays.copyOfRange(X, u, X.length));
        //System.out.println(new String(A) + " " + new String(B));

        //3. Let TL = T[0..27] || 04 and TR = T[32..55] || T[28..31] || 04 683 .
        ByteBuffer TL = ByteBuffer.allocate(4);
        TL.put(tweak,0,4);
        ByteBuffer TR = ByteBuffer.allocate(4);
        TR.put(tweak, 4,4);

        //684 4. For i from 7 to 0:
        for (int i=7; i >= 0; i--) {
            //685 i. If i is even, let m = u and W = TR, else let m = v and W =TL.
            int m =0;
            ByteBuffer W;
            if (i %2 == 0) {
                m = u;
                W = TR;
            } else {
                m = v;
                W = TL;
            }
            //ii. P = W ⊕ [i]
            //4 || [NUMradix (REV(A))]12 686 .
            ByteBuffer P = ByteBuffer.allocate(16);
            P.putInt(W.getInt(0) ^ i);
            BigInteger numRad = base.toBase10(A);
            P.put(getBytes(numRad.toByteArray(),0,12));
            //System.out.println(" P = " + Arrays.toString(P.array()));
            //687 iii Let S = REVB(CIPHREVB(K)REVB(P)).
            byte[] S = reverse(cipher(reverse(P.array())));
            //688 iv. Let y = NUM(S).
            BigInteger y = new BigInteger(1, S);
            //v. Let c = (NUMradix (REV(B))–y) mod radix m 689 .
            BigInteger c = (base.toBase10(B).subtract(y)).mod(BigInteger.valueOf(base.getRadix()).pow(m));
            //System.out.println("y = " + y + ", c = " + c);
            //vi. Let C = REV(STRm 690 radix (c)).

            char[] C = getChars(base.fromBase10(c), 0, m, base.getChar(0));
            //691 vii. Let B = A.
            //692 viii. Let A = C.
            B = A;
            A = C;
        }
        //693 5. Return A || B.
        StringBuilder sb = new StringBuilder();
        sb.append(reverse(A));
        sb.append(reverse(B));
        return sb.toString();
    }

    public static long minlen(RadixEncoding domain) {
        return MoreMath.logInt((int)domain.getRadix(), 100, RoundingMode.CEILING);
    }
    public static long maxlen(RadixEncoding domain) {
        BigDecimal max = MoreMath.log((int)domain.getRadix(), BigDecimal.valueOf(2).pow(96));
        return BigDecimal.valueOf(2).multiply(max).toBigInteger().longValue();
    }
    public byte[] cipher(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ciphertext = cipher.doFinal(data);
            return ciphertext;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] reverse(byte[] x) {
        byte[] y = new byte[x.length];
        for (int i= 0; i < x.length; i++) {
            y[i] = x[x.length - 1 - i];
        }
        return y;
    }

    private static char[] reverse(char[] x) {
        char[] y = new char[x.length];
        for (int i= 0; i < x.length; i++) {
            y[i] = x[x.length - 1 - i];
        }
        return y;
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

    public static void main(String... args) throws Exception {
        System.out.println("Range Number:    " + minlen(RadixEncoders.BASE10) + " - " + maxlen(RadixEncoders.BASE10));
        System.out.println("Range Email:     " + minlen(RadixEncoders.ASCII_EMAIL) + " - " + maxlen(RadixEncoders.ASCII_EMAIL));
        System.out.println("Range Printable: " + minlen(RadixEncoders.ASCII_PRINTABLE) + " - " + maxlen(RadixEncoders.ASCII_PRINTABLE));
        SecureRandom random = SecureRandom.getInstanceStrong();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, random);
        SecretKey key = keyGen.generateKey();

        String message = "12345678909876543210";

        //String out = F_A10(message.length(), new byte[]{5, 19, -25}, 1, new BigInteger("11111111"), key);
        FF3 ff3 = new FF3();
        FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10, new byte[]{5,19, -8, 28, 34,122,4,0});
        ff3.init(key, spec);
        String enc = ff3.encrypt(message);
        System.out.println(enc);

        String dec = ff3.decrypt(enc);
        System.out.println(dec);

        spec = new FFXAlgorithmParameterSpec(RadixEncoders.ASCII_PRINTABLE, new byte[]{5,19, -8, 28, 34,122,4,0});
        ff3.init(key, spec);
        message = "The quick brown fox.";
        enc = ff3.encrypt(message);
        System.out.println(enc);

        dec = ff3.decrypt(enc);
        System.out.println(dec);
    }
}
