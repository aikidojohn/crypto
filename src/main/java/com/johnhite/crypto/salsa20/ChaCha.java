package com.johnhite.crypto.salsa20;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class ChaCha {

    private int[] state = new int[16];
    BigInteger counter = BigInteger.ZERO;

    public ChaCha(byte[] key, byte[] nonce) {
        ByteBuffer constWrap = ByteBuffer.wrap("expand 32-byte k".getBytes());
        state[0] = constWrap.getInt(0);
        state[1] = constWrap.getInt(4);
        state[2] = constWrap.getInt(8);
        state[3] = constWrap.getInt(12);
        ByteBuffer keyWrap = ByteBuffer.wrap(key);
        state[4] = keyWrap.getInt(0);
        state[5] = keyWrap.getInt(4);
        state[6] = keyWrap.getInt(8);
        state[7] = keyWrap.getInt(12);
        state[8] = keyWrap.getInt(16);
        state[9] = keyWrap.getInt(20);
        state[10] = keyWrap.getInt(24);
        state[11] = keyWrap.getInt(28);
        ByteBuffer nonceWrap = ByteBuffer.wrap(key);
        state[14] = nonceWrap.getInt(0);
        state[15] = nonceWrap.getInt(4);
    }

    public byte[] next() {
        ByteBuffer ctr = ByteBuffer.allocate(8);
        ctr.put(counter.toByteArray());
        state[12] = ctr.getInt(0);
        state[13] = ctr.getInt(4);

        int[] output = block(state);
        ByteBuffer bb = ByteBuffer.allocate(64);
        for (int i : output) {
            bb.putInt(i);
        }

        counter = counter.add(BigInteger.ONE);
        return bb.array();
    }

    private void printState(int[] s) {
        StringBuilder sb = new StringBuilder();
        for (int i=0; i < 16; i++) {
            if (i %4 == 0) {
                sb.append('\n');
            }
            sb.append(s[i]);
            sb.append(",\t");
        }
        System.out.println(sb.toString());
    }

    private void QR(int[] in, int a, int b, int c, int d) {
        in[a] += in[b]; in[d] ^= in[a]; in[d] = (in[d] << 16) | (in[d] >>> 16);
        in[c] += in[d]; in[b] ^= in[c]; in[b] = (in[b] << 12) | (in[b] >>> 20);
        in[a] += in[b]; in[d] ^= in[a]; in[d] = (in[d] << 8) | (in[d] >>> 24);
        in[c] += in[d]; in[b] ^= in[c]; in[b] = (in[b] << 7) | (in[b] >>> 25);
    }

    private int[] block(int[] in) {
        int[] x= new int[16];
        System.arraycopy(in, 0, x, 0, 16);
        for (int i=0; i < 10; i++) {
            QR(x, 0,4,8,12);
            QR(x, 1,5,9,13);
            QR(x, 2,6,10,14);
            QR(x, 3,7,11,15);

            QR(x, 0,5,10,15);
            QR(x, 1,6,11,12);
            QR(x, 2,7,8,13);
            QR(x, 3,4,9,14);
        }
        for (int i=0; i <16; i++) {
            x[i] += in[i];
        }
        return x;
    }

    public static void main(String... args) {
        byte[] key = new byte[32];
        byte[] nonce = new byte[8];
        ChaCha c = new ChaCha(key, nonce);
        System.out.println(Hex.encodeHexString(c.next()));
        System.out.println(Hex.encodeHexString(c.next()));
    }
}
