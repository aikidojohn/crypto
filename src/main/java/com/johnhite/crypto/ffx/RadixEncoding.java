package com.johnhite.crypto.ffx;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public interface RadixEncoding {
    int getIndex(char c);

    char getChar(int index);

    long getRadix();

    /**
     * Converts the base radix number represented by the characters in symbols to a
     * base 10 number.
     *
     * @param symbols base radix number
     * @return
     */
    default BigInteger toBase10(char[] symbols) {
        final BigInteger rad = BigInteger.valueOf(getRadix());
        BigInteger x = BigInteger.ZERO;
        BigInteger radPow = BigInteger.ONE;
        for (int i=symbols.length-1; i >=0; i--) {
            x = x.add(radPow.multiply(BigInteger.valueOf(getIndex(symbols[i]))));
            radPow = radPow.multiply(rad);
        }
        return x;
    }

    /**
     * Converts the base 10 number n into a base radix representation of the number.
     *
     * @param n base 10 number to convert
     * @return
     */
    default char[] fromBase10(BigInteger n) {
        List<Character> chars = new ArrayList<>();
        final BigInteger rad = BigInteger.valueOf(getRadix());
        BigInteger val = n;
        while (val.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divAndRem = val.divideAndRemainder(rad);
            chars.add(getChar(divAndRem[1].intValue()));
            val = divAndRem[0];
        }
        char[] result = new char[chars.size()];
        int ind =0;
        for (int i=chars.size()-1; i >= 0; i--) {
            result[ind++] = chars.get(i);
        }
        return result;
    }
}
