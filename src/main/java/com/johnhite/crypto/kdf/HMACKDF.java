package com.johnhite.crypto.kdf;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.BitSet;

/**
 * https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-108.pdf
 */
public final class HMACKDF {
    private static final String MAC_ALGORITHM = "HmacSHA512";

    /**
     * Derive a 512-bit key according to NIST SP 800-108 using Hmac512 as the pseudorandom function.
     * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
     *
     * This function may be used to derive multiple, distinct keys from the same base key (called a derivation key).
     * The same inputs (derivationKey and context) will always result in the same output key material.
     *
     * @param derivationKey (Sensitive) Key used for deriving key material
     * @param context (Non-Sensitive) Context for key derivation. This does not need to be secret to maintain the security properties of the output key material.
     * @return 512 bits of derived key material.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static final byte[] deriveKeyHmac512(byte[] derivationKey, byte[] context) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(derivationKey, "HmacSHA512"));

        final byte[] label = "message authentication".getBytes();
        //Allocate a buffer to hold the input to the HMAC function.
        // length of [i] || label || 0x00 || context || [L]
        final ByteBuffer buffer = ByteBuffer.allocate(2 + label.length + 1 + context.length + 2);
        buffer.putShort((short)1); //iteration count (only need 1 iteration to produce a 512 bit key)
        buffer.put(label); //identifies the purpose of the resulting key material
        buffer.put((byte)0x00); //because the spec says to put a 0 byte here
        buffer.put(context); //information related to the derived key. This value differentiates derived keys from one another.
        buffer.putShort((short)512); //length in bits of the derived key material.
        byte[] output = mac.doFinal(buffer.array());
        return output;
    }

    public static final byte[] deriveKey(byte[] K1, byte[] label, byte[] context, short length) throws NoSuchAlgorithmException, InvalidKeyException {
        if (length % 8 != 0) {
            throw new IllegalArgumentException("Length must be a multiple of 8");
        }
        final Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(new SecretKeySpec(K1, MAC_ALGORITHM));

        final int hmacOutputBits = mac.getMacLength() * 8;
        final int n = length / hmacOutputBits + (length % hmacOutputBits == 0 ? 0 : 1);
        //bounds check on n not required because it is by definition smaller than the maximum counter value;

        final ByteBuffer buffer = ByteBuffer.allocate(n * mac.getMacLength());
        final ByteBuffer inputBuffer = ByteBuffer.allocate(2 + label.length + context.length + 2 + 1);
        inputBuffer.putShort((short)0);
        inputBuffer.put(label);
        inputBuffer.put((byte)0x00);
        inputBuffer.put(context);
        inputBuffer.putShort(length);
        for (int i = 0; i < n; i++) {
            inputBuffer.putShort(0, (short)i);
            buffer.put(mac.doFinal(inputBuffer.array()));
            mac.reset();
        }
        final int outputBytes = length / 8 + (length % 8 == 0 ? 0 : 1);
        final byte[] returnValue = new byte[outputBytes];
        buffer.rewind();
        buffer.get(returnValue, 0, outputBytes);
        buffer.clear();
        return returnValue;
    }


    public static void main(String... args) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        random.nextBytes(key);

        byte[] label = "data encryption".getBytes();
        byte[] context = "user 123 key 456".getBytes();

        HMACKDF kdf = new HMACKDF();
        byte[] derivedKey = kdf.deriveKey(key, label, context, (short)128);
        System.out.println("length: " + derivedKey.length);
        System.out.println(Hex.encodeHexString(derivedKey));

        derivedKey = kdf.deriveKey(key, label, context, (short)256);
        System.out.println("length: " + derivedKey.length);
        System.out.println(Hex.encodeHexString(derivedKey));

        derivedKey = kdf.deriveKey(key, label, context, (short)384);
        System.out.println("length: " + derivedKey.length);
        System.out.println(Hex.encodeHexString(derivedKey));

        derivedKey = kdf.deriveKey(key, label, context, (short)512);
        System.out.println("length: " + derivedKey.length);
        System.out.println(Hex.encodeHexString(derivedKey));
    }
}
