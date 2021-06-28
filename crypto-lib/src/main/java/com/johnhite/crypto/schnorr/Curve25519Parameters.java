package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

public class Curve25519Parameters implements CurveParameters {
    private static final BigInteger modulus = BigInteger.valueOf(2L).pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger aCoeff = BigInteger.valueOf(486662L);
    private static final BigInteger bCoeff = BigInteger.ONE;
    private static final BigInteger N = BigInteger.valueOf(2).pow(252).add(new BigInteger("27742317777372353535851937790883648493", 10));
    private static final BigInteger Gx = BigInteger.valueOf(9);

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public BigInteger getA() {
        return aCoeff;
    }

    @Override
    public BigInteger getB() {
        return bCoeff;
    }

    @Override
    public BigInteger getBasisX() {
        return Gx;
    }

    @Override
    public BigInteger getSubgroupSize() {
        return N;
    }
}
