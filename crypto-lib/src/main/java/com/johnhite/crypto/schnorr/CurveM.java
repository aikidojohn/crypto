package com.johnhite.crypto.schnorr;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CurveM implements EllipticCurve {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger FOUR = BigInteger.valueOf(4);

    private static CurveM curve = new CurveM();

    //y^2 = x^3 + 486662x^2 + x
    private static final BigInteger aCoeff = BigInteger.valueOf(4L);
    private static final BigInteger bCoeff = BigInteger.ONE;
    public static final BigInteger P = BigInteger.valueOf(41);
    public static final BigInteger N = BigInteger.valueOf(5);
    public static final CurvePt G = new MontgomeryCurvePt(curve, BigInteger.valueOf(9L));
    public static final CurvePt INF = new MontgomeryCurvePt(curve, P, P);

    public static CurveM getInstance() {
        return curve;
    }

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
     * Quadratic residue (square root) for fields over Z/Zp
     * Tonelli–Shanks algorithm
     * https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
     * @param x
     * @return
     */
    private BigInteger residue(BigInteger x) {
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

    public BigInteger y2(BigInteger x) {
        BigInteger xx = x.multiply(x).mod(P);
        BigInteger y2 = xx.multiply(x).mod(P).add(aCoeff.multiply(xx).mod(P)).add(x).mod(P);
        return y2;
    }

    public List<BigInteger> enumeratePoints() {
        List<BigInteger> xVals = new ArrayList<>();
        int card = 0;
        BigInteger euler = P.subtract(ONE).divide(TWO);
        for (BigInteger i = BigInteger.ZERO; i.compareTo(P) < 0; i = i.add(BigInteger.ONE)) {
            BigInteger y2 = y2(i);
            if (y2.modPow(euler, P).equals(BigInteger.ONE)) {
                BigInteger y = residue(y2);
                System.out.println(i + " : " + y + " , " + P.subtract(y));
                card += 2;
                xVals.add(i);
            }
        }
        System.out.println("Cardinality: " + card);
        return xVals;
    }

    public int printCycle(BigInteger x) {
        CurvePt origin = fromX(x);
        CurvePt pt = origin.dbl();
        int ord = 1;
        StringBuilder sb = new StringBuilder();
        sb.append(origin.toString());
        sb.append(" -> ");
        Set<CurvePt> points = new HashSet<>();
        points.add(origin);
        while (!points.contains(pt)) {
            sb.append(pt.toString());
            sb.append(", ");
            points.add(pt);
            pt = pt.add(origin);
            ord++;
        }
        sb.append("cycle ( " + pt + " )");
        sb.insert(0, "" + ord + " : ");
        System.out.println(sb.toString());
        return ord;
    }
}
