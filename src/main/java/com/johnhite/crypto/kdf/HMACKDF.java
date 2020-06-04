package com.johnhite.crypto.kdf;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-108.pdf
 */
public final class HMACKDF {
    private static final int HMAC_OUTPUT_BITS = 256;

    public final byte[] deriveKey(byte[] K1, byte[] label, byte[] context, short length) throws NoSuchAlgorithmException, InvalidKeyException {
        if (length % 8 != 0) {
            throw new IllegalArgumentException("Length must be a multiple of 8");
        }
        final int n = length / HMAC_OUTPUT_BITS + (length % HMAC_OUTPUT_BITS == 0 ? 0 : 1);
        //bounds check on n not required because it is by definition smaller than the maximum counter value;

        final Mac mac = Mac.getInstance("HmacSHA256");
        final SecretKeySpec kspec = new SecretKeySpec(K1, "HmacSHA256");
        mac.init(kspec);

        final ByteBuffer buffer = ByteBuffer.allocate(n * HMAC_OUTPUT_BITS / 8);

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
