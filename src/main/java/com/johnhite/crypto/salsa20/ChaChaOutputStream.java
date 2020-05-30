package com.johnhite.crypto.salsa20;

import java.io.IOException;
import java.io.OutputStream;

public class ChaChaOutputStream extends OutputStream {
    private OutputStream out;
    private ChaCha cipher;
    private byte[] keyStreamBuffer = new byte[64];
    private int blockCount =64;

    public ChaChaOutputStream(OutputStream out, byte[] key, byte[] nonce) {
        this.out = out;
        this.cipher = new ChaCha(key, nonce);
    }

    @Override
    public void write(int b) throws IOException {
        if (blockCount >= 64) {
            keyStreamBuffer = cipher.next();
            blockCount = 0;
        }
        out.write(b ^ keyStreamBuffer[blockCount]);
        blockCount++;
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void close() throws IOException {
        out.close();
    }
}
