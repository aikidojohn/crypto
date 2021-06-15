package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

public interface CurveParameters {
    BigInteger getModulus();
    BigInteger getA();
    BigInteger getB();
    BigInteger getBasisX();
    BigInteger getSubgroupSize();
}
