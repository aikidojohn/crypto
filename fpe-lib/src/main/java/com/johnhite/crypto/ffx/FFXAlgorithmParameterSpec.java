package com.johnhite.crypto.ffx;

import java.security.spec.AlgorithmParameterSpec;

public class FFXAlgorithmParameterSpec implements AlgorithmParameterSpec {

    private final RadixEncoding base;
    private final byte[] tweak;

    public FFXAlgorithmParameterSpec(RadixEncoding base) {
        this(base, new byte[0]);
    }
    public FFXAlgorithmParameterSpec(RadixEncoding base, byte[] tweak) {
        this.base = base;
        this.tweak = tweak;
    }

    public RadixEncoding getBase() {
        return base;
    }

    public byte[] getTweak() {
        return tweak;
    }
}
