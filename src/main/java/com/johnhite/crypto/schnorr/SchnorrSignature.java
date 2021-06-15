package com.johnhite.crypto.schnorr;

import org.apache.commons.codec.binary.Base64;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

/**
 * https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3
 * https://www.math.brown.edu/johsilve/Presentations/WyomingEllipticCurve.pdf
 */
public class SchnorrSignature {

    public static void main(String... args) throws NoSuchAlgorithmException {
        CurveM cm = CurveM.getInstance();
        List<BigInteger> xs = cm.enumeratePoints();
        boolean primeGroup = false;
        for (BigInteger xg : xs) {
            primeGroup |= BigInteger.valueOf(cm.printCycle(xg)).isProbablePrime(100);
        }
        System.out.println(primeGroup);
        //cm.printCycle(BigInteger.valueOf(2));
        //CurvePt g = CurveM.G;//Curve25519.fromX(BigInteger.valueOf(9));
        /*System.out.println(g.dbl().dbl());
        System.out.println(g.dbl().add(g).add(g));
        System.out.println(g.mul(BigInteger.valueOf(4)));
        System.out.print(g + " -> ");
        for (BigInteger i = BigInteger.valueOf(2); i.compareTo(CurveM.N) <= 0; i = i.add(BigInteger.ONE)) {
            System.out.print(g.mul(i) + ", ");
        }
        System.out.println();*/
        //CurvePt g = Curve25519.fromX(BigInteger.valueOf(9));
       // BigInteger N = Curve25519.N;
        MontgomeryCurvePt g = (MontgomeryCurvePt) CurveM.G;
        BigInteger N = CurveM.N;
        CurvePt gnn = g.mul(N.subtract(BigInteger.ONE)); //g.mul(Curve25519.N.subtract(BigInteger.ONE));
        CurvePt gn = gnn.add(g);
        MontgomeryCurvePt ggp = (MontgomeryCurvePt) g._dblProjective();
        BigInteger ggpx = g.inv(ggp.getZ()).multiply(ggp.getX()).mod(CurveM.P);
        CurvePt gga = g.dbl();
        MontgomeryCurvePt gggp = (MontgomeryCurvePt) ggp._diffAddProjective(g, g);
        BigInteger gggpx = g.inv(gggp.getZ()).multiply(gggp.getX()).mod(CurveM.P);
        CurvePt ggga = gga.add(g);
        BigInteger priv = BigInteger.valueOf(4);
        CurvePt pub = g.mul(priv);
        BigInteger k = BigInteger.valueOf(4);
        BigInteger chal = BigInteger.valueOf(1);
        BigInteger ver = k.subtract(priv.multiply(chal)).mod(N);
        CurvePt verP = g.mul(k);
        CurvePt valP = g.mul(ver).add(pub.mul(chal));

        org.bouncycastle.math.ec.custom.djb.Curve25519 bcurve = new org.bouncycastle.math.ec.custom.djb.Curve25519();

        //findSchnorrGroup();
        //Curve 25519
        final SecureRandom rand = new SecureRandom();

        //private key
        BigInteger a = new BigInteger(Curve25519.N.bitLength(), rand);
        while (a.compareTo(Curve25519.N) >= 0) {
            a = new BigInteger(Curve25519.N.bitLength(), rand);
        }

        //Public Key
        CurvePt A = Curve25519.G.mul(a);
        System.out.println("a: " + a);
        System.out.println(A);
        System.out.println("A: " + Base64.encodeBase64String(A.getX().toByteArray()));
        System.out.println("a: " + Base64.encodeBase64String(a.toByteArray()));

        //protocol
        //1. Alice computes
        BigInteger v = new BigInteger(Curve25519.N.bitLength(), rand);
        while (v.compareTo(Curve25519.N) >= 0) {
            v = new BigInteger(Curve25519.N.bitLength(), rand);
        }
        CurvePt V = Curve25519.G.mul(v);
        System.out.println("V: " + V);

        //2. Alice computes Challenge and sends to Alice
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Curve25519.G.getX().toByteArray());
        md.update(V.getX().toByteArray());
        md.update(A.getX().toByteArray());
        md.update("aikidojohn@gmail.com".getBytes());
        BigInteger c = new BigInteger(1, md.digest());
        System.out.println("c: " + Base64.encodeBase64String(c.toByteArray()));

        //3. Alice computes
        BigInteger r = v.subtract(a.multiply(c).mod(Curve25519.N)).mod(Curve25519.N);
        System.out.println("r: " + Base64.encodeBase64String(r.toByteArray()));

        //4. Bob verifies
        //if (A.compareTo(P) >= 0 || !A.modPow(Q, P).equals(BigInteger.ONE)) {
        //    System.out.println("public key A is not a valid public key");
        //}
        //Bob computes c then verifies V
        CurvePt Vp = Curve25519.G.mul(r).add(A.mul(c));
        System.out.println("Vp: " + Vp);
        if (V.getX().equals(Vp.getX())) {
            System.out.println("Signature is Valid!");
        } else {
            System.out.println("Signature is Invalid!");
        }
    }

    /**
     * Schnorr non-interactive zero knowledge proof algorithm. Based on a Fiat-Shamir transformation of the interactive proof.
     * https://tools.ietf.org/html/rfc8235
     * @throws NoSuchAlgorithmException
     */
    public static void SchnorrNIZK() throws NoSuchAlgorithmException {
        final BigInteger P = new BigInteger(1, Base64.decodeBase64("AJhEVZqGJ1O+pdDyrD8YJJD8YDG8hFr9Y67jnFmag3tpQVRV3xED63BzY0NyA+An5fs4IdmsqJo5UtMeb8uA/Ix02DuBdZ8bsasBc+zfaPEuoUrnx981iQNBaKmvF80hWIBt185l64AH4pqCRxshqaNTV2cQmagFzQPfKS9ZQ9STmd6Qfd/t16BLirRdcnVl5aXVKEkYUUEAZdrVG5toEjxg1a7MPvgFD3JqLZXV62sAhlGgDgEg5gsGMF50x0LBxGuWZWIgQyXHAFlZ8X5dKFyI0e83DHT/HYSjhPELrAF3RQqTXwpiEgXq9mDTMZ0rnKwCvEJ77S4ynuPpY6P1R0k="));
        final BigInteger Q = new BigInteger(1, Base64.decodeBase64("AKOZDvLMLfYUGR+j5EuRaT8ugbEewBYc8uzpqTvXLPGrR/bATuNuOy4N6foTcwjEJw=="));
        final BigInteger G = new BigInteger(1, Base64.decodeBase64("UBn11LVL4Sm0OyIH/7O5RRf78zupsYd1g0b10d4RfpPowqmz984jFkIFzmoXzK2tkWXRV0acjXxnkPBM+npyMZXNG061h80T4Jwvp8PtirV9JlhdrZpqtZ+6RH/JWX8RHO3sm5t1PwwUS8nIMhPDRJ61Wpisb82pjQNVym9bHowC5VXneuWlftRjEn2tFuTtY5KqeZJd4kTsFFvfRoSi9hPyt6kZKyZyWW4gAjWyzwVKkO31NkGdPD7X639gPQwjQ9UNMtAIx2VK1xSZr9PK/QFA1p5d3bsI1NF1SeRt3VcAShJ4LYOn0r+rRz9nofoAX2Tpd11DmNq5MGIJAl/NyQ=="));
        final SecureRandom rand = new SecureRandom();

        //private key
        BigInteger a = new BigInteger(Q.bitLength(), rand);
        while (a.compareTo(Q) >= 0) {
            a = new BigInteger(Q.bitLength(), rand);
        }

        //Public Key
        BigInteger A = G.modPow(a, P);
        System.out.println("A: " + Base64.encodeBase64String(A.toByteArray()));
        System.out.println("a: " + Base64.encodeBase64String(a.toByteArray()));

        //protocol
        //1. Alice computes
        BigInteger v = new BigInteger(Q.bitLength(), rand);
        while (v.compareTo(Q) >= 0) {
            v = new BigInteger(Q.bitLength(), rand);
        }
        BigInteger V = G.modPow(v, P);
        System.out.println("V: " + Base64.encodeBase64String(V.toByteArray()));

        //2. Alice computes Challenge and sends to Alice
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(G.toByteArray());
        md.update(V.toByteArray());
        md.update(A.toByteArray());
        md.update("aikidojohn@gmail.com".getBytes());
        BigInteger c = new BigInteger(1, md.digest());
        System.out.println("c: " + Base64.encodeBase64String(c.toByteArray()));

        //3. Alice computes
        BigInteger r = v.subtract(a.multiply(c).mod(Q)).mod(Q);
        System.out.println("r: " + Base64.encodeBase64String(r.toByteArray()));

        //4. Bob verifies
        if (A.compareTo(P) >= 0 || !A.modPow(Q, P).equals(BigInteger.ONE)) {
            System.out.println("public key A is not a valid public key");
        }
        //Bob computes c then verifies V
        BigInteger Vp = G.modPow(r, P).multiply(A.modPow(c,P)).mod(P);
        if (V.equals(Vp)) {
            System.out.println("Signature is Valid!");
        } else {
            System.out.println("Signature is Invalid!");
        }
    }

    public static void SchnorrInteractiveProof() {
        final BigInteger P = new BigInteger(1, Base64.decodeBase64("AJhEVZqGJ1O+pdDyrD8YJJD8YDG8hFr9Y67jnFmag3tpQVRV3xED63BzY0NyA+An5fs4IdmsqJo5UtMeb8uA/Ix02DuBdZ8bsasBc+zfaPEuoUrnx981iQNBaKmvF80hWIBt185l64AH4pqCRxshqaNTV2cQmagFzQPfKS9ZQ9STmd6Qfd/t16BLirRdcnVl5aXVKEkYUUEAZdrVG5toEjxg1a7MPvgFD3JqLZXV62sAhlGgDgEg5gsGMF50x0LBxGuWZWIgQyXHAFlZ8X5dKFyI0e83DHT/HYSjhPELrAF3RQqTXwpiEgXq9mDTMZ0rnKwCvEJ77S4ynuPpY6P1R0k="));
        final BigInteger Q = new BigInteger(1, Base64.decodeBase64("AKOZDvLMLfYUGR+j5EuRaT8ugbEewBYc8uzpqTvXLPGrR/bATuNuOy4N6foTcwjEJw=="));
        final BigInteger G = new BigInteger(1, Base64.decodeBase64("UBn11LVL4Sm0OyIH/7O5RRf78zupsYd1g0b10d4RfpPowqmz984jFkIFzmoXzK2tkWXRV0acjXxnkPBM+npyMZXNG061h80T4Jwvp8PtirV9JlhdrZpqtZ+6RH/JWX8RHO3sm5t1PwwUS8nIMhPDRJ61Wpisb82pjQNVym9bHowC5VXneuWlftRjEn2tFuTtY5KqeZJd4kTsFFvfRoSi9hPyt6kZKyZyWW4gAjWyzwVKkO31NkGdPD7X639gPQwjQ9UNMtAIx2VK1xSZr9PK/QFA1p5d3bsI1NF1SeRt3VcAShJ4LYOn0r+rRz9nofoAX2Tpd11DmNq5MGIJAl/NyQ=="));
        final SecureRandom rand = new SecureRandom();

        //private key
        BigInteger a = new BigInteger(Q.bitLength(), rand);
        while (a.compareTo(Q) >= 0) {
            a = new BigInteger(Q.bitLength(), rand);
        }

        //Public Key
        BigInteger A = G.modPow(a, P);
        System.out.println("A: " + Base64.encodeBase64String(A.toByteArray()));
        System.out.println("a: " + Base64.encodeBase64String(a.toByteArray()));

        //protocol
        //1. Alice computes
        BigInteger v = new BigInteger(Q.bitLength(), rand);
        while (v.compareTo(Q) >= 0) {
            v = new BigInteger(Q.bitLength(), rand);
        }
        BigInteger V = G.modPow(v, P);
        System.out.println("V: " + Base64.encodeBase64String(V.toByteArray()));

        //2. Bob computes Challenge and sends to Alice
        BigInteger c = new BigInteger(160, rand);
        System.out.println("c: " + Base64.encodeBase64String(c.toByteArray()));

        //3. Alice computes
        BigInteger r = v.subtract(a.multiply(c).mod(Q)).mod(Q);
        System.out.println("r: " + Base64.encodeBase64String(r.toByteArray()));

        //4. Bob verifies
        if (A.compareTo(P) >= 0 || !A.modPow(Q, P).equals(BigInteger.ONE)) {
            System.out.println("public key A is not a valid public key");
        }
        BigInteger Vp = G.modPow(r, P).multiply(A.modPow(c,P)).mod(P);
        if (V.equals(Vp)) {
            System.out.println("Signature is Valid!");
        } else {
            System.out.println("Signature is Invalid!");
        }
    }

    public static void findSchnorrGroup(String... args) {
        int subgroupSize = 384;
        int groupSize = 2048;
        SecureRandom rand = new SecureRandom();
        BigInteger q = BigInteger.probablePrime(subgroupSize,rand);
        BigInteger r = new BigInteger((groupSize-subgroupSize), rand);
        BigInteger p = q.multiply(r).add(BigInteger.ONE);
        while (!p.isProbablePrime(100)) {
            r = r.add(BigInteger.ONE);
            p = q.multiply(r).add(BigInteger.ONE);
        }
        System.out.println(p.bitLength());
        System.out.println("p: " + Base64.encodeBase64String(p.toByteArray()));
        System.out.println("q: " + Base64.encodeBase64String(q.toByteArray()));
        System.out.println("r: " + Base64.encodeBase64String(r.toByteArray()));

        BigInteger h = new BigInteger(groupSize, rand);
        BigInteger g = h.modPow(r, p);
        while(g.equals(BigInteger.ONE)) {
            h = new BigInteger(groupSize, rand);
            g = h.modPow(r, p);
        }

        System.out.println("g: " + Base64.encodeBase64String(g.toByteArray()));
    }

    public static void findSchnorrSmallG() {
        int subgroupSize = 160;
        int groupSize = 512;
        SecureRandom rand = new SecureRandom();
       // BigInteger q = BigInteger.probablePrime(subgroupSize,rand);
        BigInteger r = BigInteger.valueOf(2);
        BigInteger p = BigInteger.probablePrime(groupSize,rand);
        while (!p.subtract(BigInteger.ONE).divide(r).isProbablePrime(100)
                && !p.multiply(r).add(BigInteger.ONE).isProbablePrime(100)) {
            p = BigInteger.probablePrime(groupSize,rand);
        }
        BigInteger q = p.subtract(BigInteger.ONE).divide(r);
        System.out.println(p.bitLength());
        System.out.println("p: " + Base64.encodeBase64String(p.toByteArray()));
        System.out.println("q: " + Base64.encodeBase64String(q.toByteArray()));
        System.out.println("r: " + Base64.encodeBase64String(r.toByteArray()));

        BigInteger h = p.add(r).sqrt();
        BigInteger g = h.modPow(r, p);
        while(g.compareTo(r) != 0) {
            h = h.add(BigInteger.ONE);
            g = h.modPow(r, p);
        }

        System.out.println("g: " + Base64.encodeBase64String(g.toByteArray()));
    }
    /**
     * p: ALTsyYs5+2ZpSxxfQ5+6b7wAlAlxrlxIy0eI4SMW/MDbhW4T1pg3d/6/af2LwKnw2V6UtRzoMDpAVhohaxwtiGdm+GiPy16hKnn0xaVfjAkYSRJuXejSekV95jlxS4kNtIwOYhw6XKIEir1hb6LWD+zr9+/yVZ9DhMhN6rCTt+h7
     * q: WnZkxZz9szSlji+hz9033gBKBLjXLiRlo8RwkYt+YG3CtwnrTBu7/1+0/sXgVPhsr0pajnQYHSArDRC1jhbEM7N8NEflr1CVPPpi0q/GBIwkiTcu9Gk9Ir7zHLilxIbaRgcxDh0uUQJFXrC30WsH9nX79/kqz6HCZCb1WEnb9D0=
     * r: Ag==
     */

    /**
     * p: AJhEVZqGJ1O+pdDyrD8YJJD8YDG8hFr9Y67jnFmag3tpQVRV3xED63BzY0NyA+An5fs4IdmsqJo5UtMeb8uA/Ix02DuBdZ8bsasBc+zfaPEuoUrnx981iQNBaKmvF80hWIBt185l64AH4pqCRxshqaNTV2cQmagFzQPfKS9ZQ9STmd6Qfd/t16BLirRdcnVl5aXVKEkYUUEAZdrVG5toEjxg1a7MPvgFD3JqLZXV62sAhlGgDgEg5gsGMF50x0LBxGuWZWIgQyXHAFlZ8X5dKFyI0e83DHT/HYSjhPELrAF3RQqTXwpiEgXq9mDTMZ0rnKwCvEJ77S4ynuPpY6P1R0k=
     * q: AKOZDvLMLfYUGR+j5EuRaT8ugbEewBYc8uzpqTvXLPGrR/bATuNuOy4N6foTcwjEJw==
     * r: AO5E6TxG+mf/mUx7RnD05o50rRlWCrvi5KjvdkSgkTU4CBZm11Adnp9ESbT0rMwRTS4LN0hV3lmwSelPkKkt9mmk+TYqjyAnPrJgHKGTA8vbTEoSQX0A483jIqRYN2gEHshhPSo+7ySNpM8BLeRfmh15toKcDwaE2cT0s5kmCCs0Gvwerk7NqoZ6VDMZfzZgHtTB+v5ROf/KhThmR8QruDmncQRatomm+Bpyr/fZjTSxh1ubcQZO/oifGVXlKIN4GkedKDAvf5MTV1pvJc+4I3g=
     * g: UBn11LVL4Sm0OyIH/7O5RRf78zupsYd1g0b10d4RfpPowqmz984jFkIFzmoXzK2tkWXRV0acjXxnkPBM+npyMZXNG061h80T4Jwvp8PtirV9JlhdrZpqtZ+6RH/JWX8RHO3sm5t1PwwUS8nIMhPDRJ61Wpisb82pjQNVym9bHowC5VXneuWlftRjEn2tFuTtY5KqeZJd4kTsFFvfRoSi9hPyt6kZKyZyWW4gAjWyzwVKkO31NkGdPD7X639gPQwjQ9UNMtAIx2VK1xSZr9PK/QFA1p5d3bsI1NF1SeRt3VcAShJ4LYOn0r+rRz9nofoAX2Tpd11DmNq5MGIJAl/NyQ==
     */
}
