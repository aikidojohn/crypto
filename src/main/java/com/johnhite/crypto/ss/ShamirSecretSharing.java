package com.johnhite.crypto.ss;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import com.johnhite.crypto.codec.Base32;

public class ShamirSecretSharing {
	private final BigInteger p;
	private final int n;
	private final int k;
	
	public ShamirSecretSharing(BigInteger p, int n, int k) {
		this.p = p;
		this.n = n;
		this.k = k;
	}
	
	public List<byte[]> createShares(byte[] secret) {
		BigInteger s = new BigInteger(1, secret);
		if (s.compareTo(p) >= 0) {
			throw new RuntimeException("Secret is too large to split.");
		}
		
		SecureRandom rand = new SecureRandom();
		List<BigInteger> coefficients = new ArrayList<>();
		for (int i=0; i < k - 1; i++) {
			coefficients.add(randCoefficient(rand));
		}
		
		List<byte[]> points = new ArrayList<>();
		for (int i= 1; i < n; i++) {
			BigInteger x = BigInteger.valueOf(i);
			BigInteger y = s;
			BigInteger nx = x;
			for (int j = 0; j < coefficients.size(); j++) {
				y = y.add(coefficients.get(j).multiply(nx).mod(p)).mod(p);
				nx = nx.multiply(x).mod(p);
			}
			Point share = new Point(x, y);
			points.add(share.toByteArray());
		}
		return points;
	}
	
	public byte[] recoverSecret(byte[]... shares) {
		List<Point> points = new ArrayList<>();
		for (byte[] share : shares) {
			points.add(new Point(share));
		}
		
		return recoverSecret(points);
	}
	
	private byte[] recoverSecret(List<Point> points) {
		
		//Calculate the free coefficent using the Legrange basis polynomials
		BigInteger secret = BigInteger.ZERO;
		final int k = points.size() - 1;
		for (int j = 0; j <= k; j++) {
			BigInteger numerator = points.get(j).Y;
			BigInteger denominator = BigInteger.ONE;
			for (int m = 0; m <= k; m++) {
				if (m == j) {
					continue;
				}
				numerator = numerator.multiply(points.get(m).X.negate()).mod(p);
				denominator = denominator.multiply(points.get(j).X.subtract(points.get(m).X)).mod(p);
			}
			secret = secret.add(numerator.multiply(denominator.modInverse(p))).mod(p);
		}
		return secret.toByteArray();
	}
	
	private BigInteger randCoefficient(SecureRandom rand) {
		BigInteger r;
		do {
		    r = new BigInteger(p.bitLength(), rand);
		} while (r.compareTo(p) >= 0);
		return r;
	}
	
	private static final class Point {
		public final BigInteger X;
		public final BigInteger Y;
		public Point(BigInteger x, BigInteger y) {
			this.X = x;
			this.Y = y;
		}
		
		public Point(byte[] encoded) {
			byte x = encoded[0];
			byte[] yBytes = new byte[encoded.length-1];
			System.arraycopy(encoded, 1, yBytes, 0, encoded.length-1);
			this.X = BigInteger.valueOf(x);
			this.Y = new BigInteger(1, yBytes);
		}
		
		public final byte[] toByteArray() {
			byte xByte = X.byteValue();
			byte[] yBytes = Y.toByteArray();
			byte[] encoded = new byte[yBytes.length + 1];
			encoded[0] = xByte;
			System.arraycopy(yBytes, 0, encoded, 1, yBytes.length);
			return encoded;
		}
		
		@Override
		public final String toString() {
			return "(" + X + ", " + Y + ")";
		}
	}
	
	public static void main(String... args) {
		SecureRandom rand = new SecureRandom();
		byte[] secret = "My Secret".getBytes();
		BigInteger sint = new BigInteger(1, secret);
		BigInteger prime;
		do {
			prime = BigInteger.probablePrime(sint.bitLength(), rand);
		} while (prime.compareTo(sint) <= 0);
		
		System.out.println(prime);
		ShamirSecretSharing ss = new ShamirSecretSharing(prime, 10, 4);
		List<byte[]> shares = ss.createShares(secret);
		for (byte[] share : shares) {
			System.out.println(Base32.encodeCrockford(share));
		}
		
		byte[] recovered = ss.recoverSecret(shares.get(0), shares.get(3), shares.get(5), shares.get(7));
		System.out.print(new String(recovered));
	}
}
