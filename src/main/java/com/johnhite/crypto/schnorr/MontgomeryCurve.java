package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

public class MontgomeryCurve implements EllipticCurve {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private final Zp zp;
    private final CurveParameters params;

    public MontgomeryCurve(CurveParameters params) {
        this.params = params;
        this.zp = new Zp(params.getModulus());
    }

    public CurvePt affinePointFromX(BigInteger x) {
        return new AffinePt(this, x);
    }
    public CurvePt affinePointFromXY(BigInteger x, BigInteger y) {
        return new AffinePt(this, x, y);
    }

    public CurvePt montgomeryPointFromX(BigInteger x) {
        return new MontgomeryPt(this, x);
    }
    public CurvePt montgomeryPointFromXZ(BigInteger x, BigInteger z) {
        return new MontgomeryPt(this, x, z);
    }
    public CurvePt toAffine(CurvePt p) {
        if (p.getCoordinateSystem() == ECCoordinateSystem.MONTGOMERY) {
            return ((MontgomeryPt)p).toAffine();
        }
        return p;
    }

    public CurvePt toMontgomery(CurvePt p) {
        if (p.getCoordinateSystem() == ECCoordinateSystem.AFFINE) {
            return new MontgomeryPt(this, p.getX());
        }
        return p;
    }

    private BigInteger _inv(BigInteger x) {
        return zp.inv(x);
    }

    private BigInteger _sq(BigInteger x) {
        return zp.mul(x,x);
    }
    private BigInteger _mulf(BigInteger... ints) {
        return zp.mul(ints);
    }

    private BigInteger _addf(BigInteger... ints) {
        return zp.sum(ints);
    }

    private BigInteger _subf(BigInteger... ints) {
        return zp.diff(ints);
    }

    @Override
    public BigInteger y(BigInteger x) {
        BigInteger xx = _sq(x);
        BigInteger y2 = _addf(_mulf(xx, x), _mulf(getA(), xx), x);
        if (!getB().equals(ONE)) {
            y2 = _mulf(y2, _inv(getB()));
        }
        return zp.residue(y2);
    }

    @Override
    public BigInteger modulus() {
        return params.getModulus();
    }

    @Override
    public CurvePt infinity() {
        return null;
    }

    @Override
    public CurvePt getG() {
        return new AffinePt(this, params.getBasisX());
    }

    @Override
    public BigInteger subgroupSize() {
        return params.getSubgroupSize();
    }

    @Override
    public BigInteger getA() {
        return params.getA();
    }

    @Override
    public BigInteger getB() {
        return params.getB();
    }

    private class AffinePt extends AbstractCurvePt {

        public AffinePt(EllipticCurve curve, BigInteger x) {
            super(curve, ECCoordinateSystem.AFFINE, x, null, BigInteger.ONE);
        }

        public AffinePt(EllipticCurve curve, BigInteger x, BigInteger y) {
            super(curve, ECCoordinateSystem.AFFINE, x, y, BigInteger.ONE);
        }

        public boolean isInfinity() {
            return x.mod(zp.P).equals(BigInteger.ZERO);
        }
        public AffinePt getInfinity() {
            return new AffinePt(curve, zp.P);
        }

        @Override
        public CurvePt add(CurvePt other) {
            if (this.equals(other)) {
                return dbl();
            }
            if (x.equals(other.getX())) {
                return this.getInfinity();
            }
            if (this.isInfinity()) {
                return other;
            }
            if (((AffinePt)other).isInfinity()) {
                return this;
            }

            BigInteger A = getA();
            BigInteger B = getB();
            BigInteger ax = getX();
            BigInteger ay = getY();
            BigInteger bx = other.getX();
            BigInteger by = other.getY();
            // L = (by - ay) / (bx -ax)
            BigInteger L = _mulf(_subf(by, ay), _inv(_subf(bx, ax)));
            BigInteger LL = _mulf(L, L);
            // xr = BL^2 - A - ax - bx
            BigInteger xr = _mulf(B, LL);
            xr = _subf(xr, A, ax, bx);

            BigInteger LLL = _mulf(LL, L);
            //yr = (2ax + bx + A)L - BL^3 - ay
            BigInteger yr = _addf(_mulf(TWO, ax), bx, A);
            yr = _subf(_mulf(yr, L), _mulf(B, LLL), ay);

            return new AffinePt(curve, xr, yr);
        }

        @Override
        public CurvePt dbl() {
            if (getY().equals(ZERO)) { //why?
                return this.getInfinity();
            }
            if (this.isInfinity()) { // infinity + infinity = infinity;
                return this;
            }
            BigInteger A = getA();
            BigInteger B = getB();
            BigInteger x = getX();
            BigInteger y = getY();
            // L = (3x^2 + 2Ax + 1) / 2By
            BigInteger L = _addf(_mulf(THREE, x, x), _mulf(TWO, A, x), ONE);
            L = _mulf(L, _inv(_mulf(TWO, B, y)));
            BigInteger LL = _sq(L);
            // xr = BL^2 - A - 2x
            BigInteger xr = _subf(_mulf(B, LL), A, _mulf(TWO, x));

            BigInteger LLL = _mulf(LL, L);
            // yr = (3x+A)L - BL^3 -y
            BigInteger yr = _addf(_mulf(THREE, x), A);
            yr = _mulf(yr, L);
            yr = _subf(yr, _mulf(B, LLL), y);

            return new AffinePt(curve, xr, yr);
        }

        @Override
        public CurvePt mul(BigInteger scalar) {
            CurvePt r = this.getInfinity();
            CurvePt p = this;
            for (BigInteger i = ONE; i.compareTo(scalar) <= 0; i = i.shiftLeft(1)) {
                if (!scalar.and(i).equals(ZERO)) {
                    r = r.add(p);
                }
                p = p.dbl();
            }
            return r;
        }
    }

    private class MontgomeryPt extends AbstractCurvePt {

        public MontgomeryPt(EllipticCurve curve, BigInteger x) {
            super(curve, ECCoordinateSystem.MONTGOMERY, x, null, BigInteger.ONE);

        }

        public MontgomeryPt(EllipticCurve curve, BigInteger x, BigInteger z) {
            super(curve, ECCoordinateSystem.MONTGOMERY, x, null, z);
        }

        public AffinePt toAffine() {
            if (z.equals(BigInteger.ONE)) {
                return new AffinePt(curve, x);
            }
            //return x/z
            return new AffinePt(curve, zp.mul(x, zp.inv(z)));
        }

        public MontgomeryPt fromAffine(AffinePt p) {
            return new MontgomeryPt(p.curve, p.x);
        }
        public boolean isInfinity() {
            return x.mod(zp.P).equals(BigInteger.ZERO);
        }
        public MontgomeryPt getInfinity() {
            return new MontgomeryPt(curve, zp.P);
        }
        @Override
        public CurvePt add(CurvePt other) {
            return null;
        }

        @Override
        public CurvePt dbl() {
            if (this.isInfinity()) {
                return this;
            }
            BigInteger xx = _sq(x);
            BigInteger zz = _sq(z);
            BigInteger xr = _sq(_subf(xx, zz));
            BigInteger xz4 = _mulf(FOUR, x, z);
            BigInteger axz = _mulf(getA(), x, z);
            BigInteger zr = _mulf(xz4, _addf(xx, axz, zz));
            return new MontgomeryPt(curve, xr, zr);
        }

        /**
         * Returns (this + b) given (this - b) = p1
         * https://crypto.stackexchange.com/questions/71796/formulas-for-adding-points-on-curve25519
         *
         * @param p1    the point at (this - b)
         * @param b the point to add
         * @return
         */
        public MontgomeryPt diffAdd(MontgomeryPt p1, MontgomeryPt b) {
            if (this.equals(b)) {
                return (MontgomeryPt) dbl();
            }
            if (x.equals(b.getX())) {
                return getInfinity();
            }
            if (this.isInfinity()) {
                return b;
            }
            if (b.isInfinity()) {
                return this;
            }
            BigInteger ab = _mulf(_subf(x, z), _addf(b.getX(), b.getZ()));
            BigInteger cd = _mulf(_addf(x, z), _subf(b.getX(), b.getZ()));
            BigInteger xr1 = _addf(cd, ab);
            BigInteger xr = _mulf(p1.getZ(), _sq(xr1));
            BigInteger zr1 = _subf(cd, ab);
            BigInteger zr = _mulf(p1.getX(), _sq(zr1));
            return new MontgomeryPt(curve, xr, zr);
        }

        @Override
        public CurvePt mul(BigInteger scalar) {
            if (this.isInfinity()) {
                return this;
            }
            MontgomeryPt r0 = this.getInfinity();
            MontgomeryPt r1 = this;
            BigInteger m = TWO.pow(scalar.bitLength()-1);
            for (BigInteger i = m; i.compareTo(BigInteger.ZERO) > 0; i = i.shiftRight(1)) {
                if (scalar.and(i).equals(ZERO)) { //zero bit?
                    r1 = r0.diffAdd(this, r1);
                    r0 = (MontgomeryPt) r0.dbl();
                } else {
                    r0 = r0.diffAdd(this, r1);
                    r1 = (MontgomeryPt) r1.dbl();
                }
            }
            return r0;
        }
    }

    public static void main (String... args) {
        MontgomeryCurve curve = new MontgomeryCurve(new CurveMParameters());
        AffinePt g = (AffinePt) curve.toAffine(curve.getG());
        MontgomeryPt gm = (MontgomeryPt)curve.toMontgomery(curve.getG());
        BigInteger N = curve.subgroupSize();

        CurvePt ggm = gm.mul(BigInteger.valueOf(4));
        CurvePt gggm = gm.mul(BigInteger.valueOf(5));
        CurvePt gg = g.mul(BigInteger.valueOf(4));
        CurvePt ggg = g.mul(BigInteger.valueOf(5));
        CurvePt ggma = curve.toAffine(ggm);
        CurvePt gggma = curve.toAffine(gggm);
        BigInteger priv = BigInteger.valueOf(5);
        CurvePt pub = gm.mul(priv);
        BigInteger k = BigInteger.valueOf(15);
        BigInteger chal = BigInteger.valueOf(2);
        BigInteger ver = k.subtract(priv.multiply(chal)).mod(N);
        CurvePt verP = gm.mul(k);
        //CurvePt valP = gm.mul(ver).add(pub.mul(chal));
        CurvePt valP = ((MontgomeryPt)gm.mul(ver)).diffAdd((MontgomeryPt) verP, (MontgomeryPt) pub.mul(chal));
    }
}
