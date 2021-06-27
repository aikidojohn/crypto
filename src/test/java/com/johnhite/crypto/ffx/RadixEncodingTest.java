package com.johnhite.crypto.ffx;

import org.junit.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class RadixEncodingTest {

    @Test
    public void testFromBase10Performance() {
        BigInteger mil = new BigInteger("63300212705268780712873612318755528348105388191280236591441609518085069433");
        List<BigInteger> values = new ArrayList<>();
        for (int j = 0; j < 100000; j++) {
            values.add(mil.multiply(BigInteger.valueOf(j)));
        }

        List<char[]> result = new ArrayList<>();
        long start = System.currentTimeMillis();
        for (int j = 0; j < 100000; j++) {
            result.add(RadixEncoders.BASE36.fromBase10(values.get(j)));
        }
        long end = System.currentTimeMillis();
        System.out.println("Last value: " + new String(result.get(result.size()-1)));
        System.out.println("fromBase10 Time: " + (end - start));
    }

    @Test
    public void testToBase10Performance() {
        Random rand = new Random();
        int radix = (int) RadixEncoders.BASE36.getRadix();
        List<char[]> values = new ArrayList<>();
        for (int j = 0; j < 100000; j++) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 50; i++) {
                sb.append(RadixEncoders.BASE36.getChar(rand.nextInt(radix)));
            }
            values.add(sb.toString().toCharArray());
        }
        List<BigInteger> result = new ArrayList<>();
        long start = System.currentTimeMillis();
        for (int j = 0; j < 100000; j++) {
            result.add(RadixEncoders.BASE36.toBase10(values.get(j)));
        }
        long end = System.currentTimeMillis();
        System.out.println("Last value: " + result.get(result.size()-1));
        System.out.println("toBase10 Time: " + (end - start));
    }

    @Test
    public void testAccurate() {
        BigInteger val = RadixEncoders.BASE36.toBase10("lo3jk".toCharArray());
        System.out.println(val);
        char[] result = RadixEncoders.BASE36.fromBase10(val);
        System.out.println(new String(result));
    }
}
