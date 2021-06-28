package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

public class CurveMParameters implements CurveParameters {
    private static final BigInteger modulus = BigInteger.valueOf(41);
    private static final BigInteger aCoeff = BigInteger.valueOf(4);
    private static final BigInteger bCoeff = BigInteger.ONE;
    private static final BigInteger N = BigInteger.valueOf(5);
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
