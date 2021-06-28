package com.johnhite.crypto.ffx;

import java.math.BigInteger;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public final class RadixEncoders {

    public static final RadixEncoding ASCII_PRINTABLE = new AsciiPrintableEncoding();
    public static final RadixEncoding ASCII_DOMAIN = new AsciiEncoding();
    public static final RadixEncoding ASCII_EMAIL = new AsciiEmail();
    public static final RadixEncoding BASE10 = new Base10Encoding();
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

    private static class TableRadixEncoding extends RadixEncoding {
        protected char[] table;
        protected Map<Character, Integer> indices = new HashMap<>();
        protected TableRadixEncoding(String tableChars) {
            table = tableChars.toCharArray();
            for (int i =0; i< table.length; i++) {
                indices.put(table[i], i);
            }
        }
        public Integer internalGetIndex(char c) {
            return indices.get(c);
        }
        public Character internalGetChar(int index) {
            return table[index];
        }
        public char[] getChars(Collection<Integer> ints) {
            char[] chars = new char[ints.size()];
            int index = 0;
            for (int i : ints) {
                chars[index++] = table[i];
            }
            return chars;
        }
        public long getRadix() {
            return table.length;
        }
    }

    private static class Base10Encoding extends TableRadixEncoding {
        public Base10Encoding() {
            super("0123456789");
        }
    }

    private static class Base36Encoding extends TableRadixEncoding {
        public Base36Encoding() {
            super("0123456789abcdefghijklmnopqrstuvwxyz");
        }
    }

    private static class Base16Encoding extends TableRadixEncoding {
        public Base16Encoding() {
            super("0123456789abcdef");
        }
    }

    private static class AsciiPrintableEncoding extends TableRadixEncoding {
        public AsciiPrintableEncoding() {
            super("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ");
        }
    }

    private static class AsciiEncoding extends TableRadixEncoding {
        public AsciiEncoding() {
            super("-.0123456789abcdefghijklmnopqrstuvwxyz");
        }
    }

    private static class AsciiEmail extends TableRadixEncoding {
        public AsciiEmail() {
            super("!#$%&'*+-./0123456789=?ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz{|}~");
        }
    }

    private static class AsciiName extends TableRadixEncoding {
        public AsciiName() {
            super("'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        }
    }
}
