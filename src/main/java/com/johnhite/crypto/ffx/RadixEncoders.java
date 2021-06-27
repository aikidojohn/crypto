package com.johnhite.crypto.ffx;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public final class RadixEncoders {

    public static final RadixEncoding ASCII_PRINTABLE = new AsciiPrintableEncoding();
    public static final RadixEncoding ASCII_DOMAIN = new AsciiEncoding();
    public static final RadixEncoding ASCII_EMAIL = new AsciiEmail();
    public static final RadixEncoding ASCII_NAME = new AsciiName();
    public static final RadixEncoding NUMBER = new Base10Encoding();
    public static final RadixEncoding BASE36 = new Base36Encoding();
    public static final RadixEncoding BASE16 = new Base16Encoding();

    private RadixEncoders() {}

    public static BigInteger toBase10(String alpha, RadixEncoding domain) {
        BigInteger radix = BigInteger.valueOf(domain.getRadix());
        char[] chars = alpha.toCharArray();
        BigInteger val = BigInteger.ZERO;
        BigInteger place = BigInteger.ONE;
        for (int i = chars.length -1; i >=0; i--) {
            int number = domain.getIndex(chars[i]);
            val = val.add(place.multiply(BigInteger.valueOf(number)));
            place = place.multiply(radix);
        }
        return val;
    }

    public static String fromBase10(BigInteger val, RadixEncoding domain) {
        BigInteger radix = BigInteger.valueOf(domain.getRadix());
        StringBuilder alpha = new StringBuilder();
        BigInteger d = val.divide(radix);
        BigInteger r = val.mod(radix);
        alpha.insert(0, domain.getChar(r.intValue()));
        while (d.compareTo(BigInteger.ZERO) > 0) {
            r = d.mod(radix);
            d = d.divide(radix);
            alpha.insert(0, domain.getChar(r.intValue()));
        }
        return alpha.toString();
    }

    private static class Base10Encoding implements RadixEncoding {
        private char[] table = "0123456789".toCharArray();
        private Map<Character, Integer> indices = new HashMap<>();
        public Base10Encoding() {
            for (int i =0; i< table.length; i++) {
                indices.put(table[i], i);
            }
        }
        public int getIndex(char c) {
            return indices.get(c);
        }
        public char getChar(int index) {
            return table[index];
        }
        public long getRadix() {
            return table.length;
        }
    }
    private static class Base36Encoding implements RadixEncoding {
        private char[] table = "0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
        private Map<Character, Integer> indices = new HashMap<>();
        public Base36Encoding() {
            for (int i =0; i< table.length; i++) {
                indices.put(table[i], i);
            }
        }
        public int getIndex(char c) {
            return indices.get(c);
        }
        public char getChar(int index) {
            return table[index];
        }
        public long getRadix() {
            return table.length;
        }
    }

    private static class Base16Encoding implements RadixEncoding {
        private char[] table = "0123456789abcdef".toCharArray();
        private Map<Character, Integer> indices = new HashMap<>();
        public Base16Encoding() {
            for (int i =0; i< table.length; i++) {
                indices.put(table[i], i);
            }
        }
        public int getIndex(char c) {
            return indices.get(c);
        }
        public char getChar(int index) {
            return table[index];
        }
        public long getRadix() {
            return table.length;
        }
    }

    private static class AsciiPrintableEncoding implements RadixEncoding {
        private char[] table = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ".toCharArray();
        private Map<Character, Integer> indices = new HashMap<>();
        public AsciiPrintableEncoding() {
            for (int i =0; i< table.length; i++) {
                indices.put(table[i], i);
            }
        }
        public int getIndex(char c) {
            return indices.get(c);
        }
        public char getChar(int index) {
            return table[index];
        }
        public long getRadix() {
            return table.length;
        }
    }

    private static class AsciiEncoding implements RadixEncoding {
        private char[] table = "-.0123456789abcdefghijklmnopqrstuvwxyz".toCharArray();
        private Map<Character, Integer> indices = new HashMap<>();
        public AsciiEncoding() {
            for (int i =0; i< table.length; i++) {
                indices.put(table[i], i);
            }
        }
        public int getIndex(char c) {
            return indices.get(c);
        }
        public char getChar(int index) {
            return table[index];
        }
        public long getRadix() {
            return table.length;
        }
    }

    private static class AsciiEmail implements RadixEncoding {
        private char[] table = "!#$%&'*+-./0123456789=?ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz{|}~".toCharArray();
        private Map<Character, Integer> indices = new HashMap<>();
        public AsciiEmail() {
            for (int i =0; i< table.length; i++) {
                indices.put(table[i], i);
            }
        }
        public int getIndex(char c) {
            return indices.get(c);
        }
        public char getChar(int index) {
            return table[index];
        }
        public long getRadix() {
            return table.length;
        }
    }

    private static class AsciiName implements RadixEncoding {
        private char[] table = "'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();
        private Map<Character, Integer> indices = new HashMap<>();
        public AsciiName() {
            for (int i =0; i< table.length; i++) {
                indices.put(table[i], i);
            }
        }
        public int getIndex(char c) {
            return indices.get(c);
        }
        public char getChar(int index) {
            return table[index];
        }
        public long getRadix() {
            return table.length;
        }
    }
}
