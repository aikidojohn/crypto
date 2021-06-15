package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

public class EllipticCurvePt implements CurvePt {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);

    private final EllipticCurve curve;
    private final BigInteger x;
    private final BigInteger y;
    private final BigInteger P;

    public EllipticCurvePt(EllipticCurve curve, BigInteger x) {
        this.curve = curve;
        this.x = x;
        this.P = curve.modulus();
        this.y = curve.y(x);
    }

    public EllipticCurvePt(EllipticCurve curve, BigInteger x, BigInteger y) {
        this.curve = curve;
        this.x = x;
        this.P = curve.modulus();
        this.y = y;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }
    public BigInteger getZ() {
        return ONE;
    }
    public ECCoordinateSystem getCoordinateSystem() {
        return ECCoordinateSystem.AFFINE;
    }

    public CurvePt add(CurvePt other) {
        return _add(other.getX(), other.getY());
    }

    private CurvePt _add(BigInteger bx, BigInteger by) {
        BigInteger L = by.subtract(y).mod(P);
        L = L.multiply(inv(bx.subtract(x).mod(P)));
        BigInteger xr = L.multiply(L).mod(P).subtract(x).mod(P).subtract(bx).mod(P);
        //don't need to worry about the y value but equation is
        BigInteger yr = L.multiply(x.subtract(xr).mod(P)).mod(P).subtract(y).mod(P);
        if (x.equals(P)) { // zero check
            return new EllipticCurvePt(curve, bx, by);
        }
        if (bx.equals(P)) { // zero check
            return this;
        }
        return new EllipticCurvePt(curve, xr, yr);
    }

    public CurvePt dbl() {
        BigInteger L = THREE.multiply(x.multiply(x).mod(P)).mod(P).add(curve.getA()).mod(P)
                .multiply(inv(TWO.multiply(y).mod(P))).mod(P);
        BigInteger xr = L.multiply(L).mod(P).subtract(x.multiply(TWO)).mod(P);
        BigInteger yr = L.multiply(x.subtract(xr).mod(P)).mod(P).subtract(y).mod(P); // ?? trying to find -y. Is this P - y?
        if (x.equals(P)) { // zero check
            return this;
        }
        return new EllipticCurvePt(curve, xr, yr);
    }

    public CurvePt mul(BigInteger scalar) {
        CurvePt r = new EllipticCurvePt(curve, P);
        CurvePt p = this;
        int m = scalar.bitLength();
        for (BigInteger i = ONE; i.compareTo(scalar) <= 0; i = i.shiftLeft(1)) {
            if (!scalar.and(i).equals(ZERO)) {
                r = r.add(p);
            }
            p = p.dbl();
        }
        return r;
    }

    private BigInteger inv(BigInteger x) {
        return x.modPow(P.subtract(TWO), P);
    }

    @Override
    public String toString() {
        return "CurvePt{" +
                "x=" + x +
                ", y=" + getY() +
                '}';
    }
}
