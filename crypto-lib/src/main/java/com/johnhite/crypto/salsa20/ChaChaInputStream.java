package com.johnhite.crypto.salsa20;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class ChaChaInputStream extends InputStream {
    private InputStream in;
    private ChaCha cipher;
    private byte[] keyStreamBuffer = new byte[64];
    private int blockCount =64;

    public ChaChaInputStream(InputStream in, byte[] key, byte[] nonce) {
        this.in = in;
        this.cipher = new ChaCha(key, nonce);
    }

    @Override
    public int read() throws IOException {
        if (blockCount >= 64) {
            keyStreamBuffer = cipher.next();
            blockCount = 0;
        }
        int next = in.read() ^ keyStreamBuffer[blockCount];
        blockCount++;
        return next;
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
