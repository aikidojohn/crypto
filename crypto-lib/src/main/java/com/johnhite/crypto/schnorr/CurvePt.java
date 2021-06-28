package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

public interface CurvePt {
    ECCoordinateSystem getCoordinateSystem();
    CurvePt add(CurvePt other);
    CurvePt dbl();
    CurvePt mul(BigInteger scalar);
    BigInteger getX();
    BigInteger getY();
    BigInteger getZ();
}
