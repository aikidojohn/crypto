package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

public class Curve25519 implements EllipticCurve {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger FOUR = BigInteger.valueOf(4);

    private static Curve25519 curve = new Curve25519();

    //y^2 = x^3 + 486662x^2 + x
    private static final BigInteger aCoeff = BigInteger.valueOf(486662L);
    private static final BigInteger bCoeff = BigInteger.ONE;
    public static final BigInteger P = BigInteger.valueOf(2L).pow(255).subtract(BigInteger.valueOf(19));
    public static final BigInteger N = BigInteger.valueOf(2L).pow(252).add(new BigInteger("27742317777372353535851937790883648493", 10));
    public static final CurvePt G = new MontgomeryCurvePt(curve, BigInteger.valueOf(9L));
    public static final CurvePt INF = new MontgomeryCurvePt(curve, P, P);

    public static CurvePt fromX(BigInteger x) {
        return new MontgomeryCurvePt(curve, x);
    }

    public BigInteger getA() {
        return aCoeff;
    }

    public BigInteger getB() {
        return bCoeff;
    }
    public BigInteger subgroupSize() {
        return N;
    }

    public BigInteger y(BigInteger x) {
        BigInteger xx = x.multiply(x).mod(P);
        BigInteger y2 = xx.multiply(x).mod(P).add(aCoeff.multiply(xx).mod(P)).add(x).mod(P);
        return residue(y2);
    }

    /**
     * https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
     *
     * @param x
     * @return
     */
    private BigInteger residue(BigInteger x) {
        // x^(p+1)/4 mod p
        BigInteger PMinusOne = P.subtract(ONE);
        BigInteger E = PMinusOne.divide(TWO);
        BigInteger Q = E;
        BigInteger S = ONE;
        while (!Q.testBit(0)) {
            Q = Q.divide(TWO);
            S = S.add(ONE);
        }
        BigInteger z = ONE;
        BigInteger euler = z.modPow(E, P);
        while (!euler.equals(PMinusOne)) {
            z = z.add(ONE);
            euler = z.modPow(E, P);
        }

        BigInteger M = S;
        BigInteger c = z.modPow(Q, P);
        BigInteger t = x.modPow(Q, P);
        BigInteger R = x.modPow(Q.add(ONE).divide(TWO), P);

        while (t.compareTo(ONE) > 0) { //figure out condition
            BigInteger i = ONE;
            BigInteger tp = t.modPow(TWO, P);
            while (!tp.equals(ONE)) {
                i = i.add(ONE);
                tp = tp.modPow(TWO, P);
            }
            BigInteger b = c.modPow(TWO.pow(M.subtract(i).subtract(ONE).intValue()), P);
            M = i;
            c = b.modPow(TWO, P);
            t = t.multiply(c).mod(P);
            R = R.multiply(b).mod(P);
        }
        if (t.equals(ONE)) return R;
        return ZERO;
        //return x.modPow(P.add(ONE).divide(FOUR), P);
    }

    @Override
    public BigInteger modulus() {
        return P;
    }

    @Override
    public CurvePt infinity() {
        return INF;
    }

    @Override
    public CurvePt getG() {
        return G;
    }
}
