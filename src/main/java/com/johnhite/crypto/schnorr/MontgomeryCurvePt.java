package com.johnhite.crypto.schnorr;

import java.math.BigInteger;
import java.util.Objects;

public class MontgomeryCurvePt implements CurvePt {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);

    private final EllipticCurve curve;
    private final BigInteger x;
    private BigInteger y;
    private final BigInteger z;
    private final BigInteger P;

    public MontgomeryCurvePt(EllipticCurve curve, BigInteger x) {
        this.curve = curve;
        this.x = x;
        this.P = curve.modulus();
        this.y = curve.y(x);
        this.z = ONE;
    }

    public MontgomeryCurvePt(EllipticCurve curve, BigInteger x, BigInteger y) {
        this.curve = curve;
        this.x = x;
        this.P = curve.modulus();
        this.y = y;
        this.z = ONE;
    }

    MontgomeryCurvePt(EllipticCurve curve, BigInteger x, BigInteger y, BigInteger z) {
        this.curve = curve;
        this.x = x;
        this.P = curve.modulus();
        this.y = y;
        this.z = z;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    public BigInteger getZ() {
        return z;
    }

    public ECCoordinateSystem getCoordinateSystem() {
        return ECCoordinateSystem.AFFINE;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MontgomeryCurvePt that = (MontgomeryCurvePt) o;
        return x.equals(that.x) && y.equals(that.y) && P.equals(that.P);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y, P);
    }

    public CurvePt add(CurvePt other) {
        if (this.equals(other)) {
            return dbl();
        }
        if (x.equals(other.getX())) {
            return curve.infinity();
        }
        if (this.equals(curve.infinity())) {
            return other;
        }
        if (other.equals(curve.infinity())) {
            return this;
        }
        return _add(other.getX(), other.getY());
    }

    /**
     * Returns (this + other) given (this - other) = p1
     * https://crypto.stackexchange.com/questions/71796/formulas-for-adding-points-on-curve25519
     *
     * @param p1    the point at (this - other)
     * @param other the point to add
     * @return
     */
    public CurvePt _diffAddProjective(MontgomeryCurvePt p1, MontgomeryCurvePt other) {
        BigInteger ab = _mulf(_subf(x, z), _addf(other.getX(), other.getZ()));
        BigInteger cd = _mulf(_addf(x, z), _subf(other.getX(), other.getZ()));
        BigInteger xr1 = _addf(cd, ab);
        BigInteger xr = _mulf(p1.getZ(), _mulf(xr1, xr1));
        BigInteger zr1 = _subf(cd, ab);
        BigInteger zr = _mulf(p1.getX(), _mulf(zr1, zr1));
        return new MontgomeryCurvePt(curve, xr, ONE, zr);
    }

    public CurvePt _dblProjective() {
        BigInteger xx = _mulf(x, x);
        BigInteger zz = _mulf(z, z);
        BigInteger xr = _subf(xx, zz);
        xr = _mulf(xr, xr);
        BigInteger xz4 = _mulf(FOUR, x, z);
        BigInteger axz = _mulf(curve.getA(), x, z);
        BigInteger zr = _mulf(xz4, _addf(xx, axz, zz));
        return new MontgomeryCurvePt(curve, xr, ONE, zr);
    }

    private CurvePt _add(BigInteger bx, BigInteger by) {
        BigInteger A = curve.getA();
        BigInteger B = curve.getB();
        // L = (by - y) / (bx -x)
        BigInteger L = _mulf(_subf(by, y), inv(_subf(bx, x)));
        BigInteger LL = _mulf(L, L);
        // xr = BL^2 - A - x - bx
        BigInteger xr = _mulf(B, LL);
        xr = _subf(xr, A, x, bx);

        BigInteger LLL = _mulf(LL, L);
        //yr = (2x + bx + A)L - BL^3 - y
        BigInteger yr = _addf(_mulf(TWO, x), bx, A);
        yr = _subf(_mulf(yr, L), _mulf(B, LLL), y);
        //BigInteger yr = _subf(P, curve.y(xr));

        return new MontgomeryCurvePt(curve, xr, yr);
    }

    public CurvePt dbl() {
        if (this.getY().equals(ZERO)) { //why?
            return curve.infinity();
        }
        if (this.equals(curve.infinity())) { // infinity + infinity = infinity;
            return this;
        }
        BigInteger A = curve.getA();
        BigInteger B = curve.getB();
        // L = (3x^2 + 2Ax + 1) / 2By
        BigInteger L = _addf(_mulf(THREE, x, x), _mulf(TWO, A, x), ONE);
        L = _mulf(L, inv(_mulf(TWO, B, y)));
        BigInteger LL = _mulf(L, L);
        // xr = BL^2 - A - 2x
        BigInteger xr = _subf(_mulf(B, LL), A, _mulf(TWO, x));

        BigInteger LLL = _mulf(LL, L);
        // yr = (3x+A)L - BL^3 -y
        BigInteger yr = _addf(_mulf(THREE, x), A);
        yr = _mulf(yr, L);
        yr = _subf(yr, _mulf(B, LLL), y);
        //BigInteger yr = _subf(P, curve.y(xr));

        return new MontgomeryCurvePt(curve, xr, yr);
    }

    public CurvePt mul(BigInteger scalar) {
        CurvePt r = curve.infinity();
        CurvePt p = this;
        for (BigInteger i = ONE; i.compareTo(scalar) <= 0; i = i.shiftLeft(1)) {
            if (!scalar.and(i).equals(ZERO)) {
                r = r.add(p);
            }
            p = p.dbl();
        }
        return r;
    }

    public BigInteger inv(BigInteger x) {
        return x.modPow(P.subtract(TWO), P);
    }

    private BigInteger _mulf(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(P);
    }

    private BigInteger _mulf(BigInteger a, BigInteger b, BigInteger c) {
        return a.multiply(b).mod(P).multiply(c).mod(P);
    }

    private BigInteger _addf(BigInteger a, BigInteger b) {
        return a.add(b).mod(P);
    }

    private BigInteger _addf(BigInteger a, BigInteger b, BigInteger c) {
        return a.add(b).mod(P).add(c).mod(P);
    }

    private BigInteger _subf(BigInteger a, BigInteger b) {
        return a.subtract(b).mod(P);
    }

    private BigInteger _subf(BigInteger a, BigInteger b, BigInteger c) {
        return a.subtract(b).mod(P).subtract(c).mod(P);
    }

    private BigInteger _subf(BigInteger a, BigInteger b, BigInteger c, BigInteger d) {
        return a.subtract(b).mod(P).subtract(c).mod(P).subtract(d).mod(P);
    }

    @Override
    public String toString() {
        if (this.equals(curve.infinity())) {
            return "CurvePt{ infinity }";
        }
        if (y == null) {
            return "CurvePt{" +
                    "x=" + x +
                    ", z=" + z +
                    '}';
        }
        return "CurvePt{" +
                "x=" + x +
                ", y=" + y +
                (z.equals(ONE) ? "" : (", z=" + z)) +
                '}';
    }
}
