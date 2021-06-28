package com.johnhite.crypto.ffx;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

public abstract class RadixEncoding {

    public boolean isValidEncoding(char[] chars) {
        for (char c : chars) {
            if (null == internalGetIndex(c)) {
                return false;
            }
        }
        return true;
    }

    public int getIndex(char c) {
        Integer i = internalGetIndex(c);
        if (i == null) {
            throw new IllegalArgumentException("Input is not a valid for this radix encoding");
        }
        return i;
    }

    public char getChar(int index){
        if (index < 0 || index >= getRadix()) {
            throw new IllegalArgumentException("Input is not a valid for this radix encoding");
        }
        return internalGetChar(index);
    }

    public int[] getIndices(char[] chars) {
        int[] ints = new int[chars.length];
        for (int i = 0; i < chars.length; i++) {
            ints[i] = getIndex(chars[i]);
        }
        return ints;
    }

    public char[] getChars(int[] ints) {
        char[] chars = new char[ints.length];
        for (int i = 0; i < ints.length; i++) {
            chars[i] = getChar(ints[i]);
        }
        return chars;
    }

    public char[] getChars(Collection<Integer> ints) {
        char[] chars = new char[ints.size()];
        int index = 0;
        for (int i : ints) {
            chars[index++] = getChar(i);
        }
        return chars;
    }

    public abstract long getRadix();
    protected abstract Integer internalGetIndex(char c);
    protected abstract Character internalGetChar(int index);

    /**
     * Converts the base radix number represented by the characters in symbols to a
     * base 10 number.
     *
     * @param symbols base radix number
     * @return
     */
    public BigInteger toBase10(char[] symbols) {
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
    public char[] fromBase10(BigInteger n) {
        LinkedList<Integer> ints = new LinkedList<>();
        final BigInteger rad = BigInteger.valueOf(getRadix());
        BigInteger val = n;
        while (val.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] divAndRem = val.divideAndRemainder(rad);
            ints.addFirst(divAndRem[1].intValue());
            val = divAndRem[0];
        }

        char[] result = getChars(ints);
        return result;
    }
}
