package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

public interface EllipticCurve {
    BigInteger y(BigInteger x);
    BigInteger modulus();
    CurvePt infinity();
    CurvePt getG();
    BigInteger subgroupSize();
    BigInteger getA();
    BigInteger getB();
}
