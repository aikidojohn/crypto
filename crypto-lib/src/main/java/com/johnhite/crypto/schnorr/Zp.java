package com.johnhite.crypto.schnorr;

import java.math.BigInteger;

/**
 * The discrete field of Z/Zp
 */
public class Zp {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);

    public final BigInteger P;

    public Zp(BigInteger P) {
        this.P = P;
    }

    public BigInteger sum(BigInteger... ints) {
        BigInteger s = ZERO;
        for (BigInteger i : ints) {
            s = s.add(i).mod(P);
        }
        return s;
    }

    public BigInteger diff(BigInteger... ints) {
        BigInteger s = ints[0];
        for (int i = 1; i < ints.length; i++) {
            s = s.subtract(ints[i]).mod(P);
        }
        return s;
    }

    public BigInteger mul(BigInteger... ints) {
        BigInteger s = ONE;
        for (BigInteger i : ints) {
            s = s.multiply(i).mod(P);
        }
        return s;
    }

    public BigInteger pow(BigInteger x, BigInteger e) {
        return x.modPow(e, P);
    }

    /**
     * Returns a / b in the field. More accurately returns
     * a * b^-1
     * @param a
     * @param b
     * @return
     */
    public BigInteger div(BigInteger a, BigInteger b) {
        return a.multiply(inv(b)).mod(P);
    }

    /**
     * Returns the multiplicative inverse x^-1
     * @param x
     * @return
     */
    public BigInteger inv(BigInteger x) {
        return x.modPow(P.subtract(TWO), P);
    }

    /**
     * Quadratic residue (square root) for fields over Z/Zp
     * Tonelli–Shanks algorithm
     * https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
     * @param x
     * @return
     */
    public BigInteger residue(BigInteger x) {
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
}
