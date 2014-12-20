package com.johnhite.crypto.codec;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of Base 32 encoding according to RFC 4648 {@link http://www.ietf.org/rfc/rfc4648.txt} 
 * with support for additional alphabets. This implementation includes the two alphabets provided by 
 * RFC 4648 as well as Douglas Crockford's alphabet {@link http://www.crockford.com/wrmg/base32.html}.
 * 
 * @author jhite
 *
 */
public class Base32 {
    private static final byte MASK_5BITS = 0x1f;
    private static final CharacterMap crockfordCharSet = new CrockfordCharacterMap();
    private static final CharacterMap rfcCharSet = new RfcCharacterMap();
    private static final CharacterMap rfcHexCharSet = new RfcExtendedHexCharacterMap();

    public static String encode(byte[] value) {
        return encode(value, crockfordCharSet);
    }
    public static String encodeRFC(byte[] value) {
        return encode(value, rfcCharSet);
    }
    public static String encodeRFCHex(byte[] value) {
        return encode(value, rfcHexCharSet);
    }
    public static String encodeCrockford(byte[] value) {
        return encode(value, crockfordCharSet);
    }
    private static int u(byte b) {
        return Byte.toUnsignedInt(b);
    }
    public static String encode(byte[] value, CharacterMap charSet) {
        final StringBuilder sb = new StringBuilder();
        final int remainder = value.length % 5;

        for (int i = 0; i < value.length - remainder; i+=5) {
            int ind = i;
            sb.append(charSet.forDigit(u(value[ind]) >>> 3 & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 2 | u(value[++ind]) >>> 6) & MASK_5BITS));
            sb.append(charSet.forDigit((u(value[ind]) >>> 1) & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 4 | u(value[++ind]) >>> 4) & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 1 | u(value[++ind]) >>> 7) & MASK_5BITS));
            sb.append(charSet.forDigit(u(value[ind]) >>> 2 & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 3 | u(value[++ind]) >>> 5) & MASK_5BITS));
            sb.append(charSet.forDigit(value[ind] & MASK_5BITS));
        }
        
        int ind = value.length - remainder;
        if (remainder == 1) {
            sb.append(charSet.forDigit(u(value[ind]) >>> 3 & MASK_5BITS));
            sb.append(charSet.forDigit(value[ind] << 2 & MASK_5BITS));
        }
        else if (remainder == 2) {
            sb.append(charSet.forDigit(u(value[ind]) >>> 3 & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 2 | u(value[++ind]) >>> 6) & MASK_5BITS));
            sb.append(charSet.forDigit(u(value[ind]) >>> 1 & MASK_5BITS));
            sb.append(charSet.forDigit(value[ind] << 4 & MASK_5BITS));
        }
        else if (remainder == 3) {
            sb.append(charSet.forDigit(u(value[ind]) >>> 3 & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 2 | u(value[++ind]) >>> 6) & MASK_5BITS));
            sb.append(charSet.forDigit(u(value[ind]) >>> 1 & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 4 | u(value[++ind]) >>> 4) & MASK_5BITS));
            sb.append(charSet.forDigit(value[ind] << 1 & MASK_5BITS));
        }
        else if (remainder == 4) {
            sb.append(charSet.forDigit(u(value[ind]) >>> 3 & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 2 | u(value[++ind]) >>> 6) & MASK_5BITS));
            sb.append(charSet.forDigit(u(value[ind]) >>> 1 & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 4 | u(value[++ind]) >>> 4) & MASK_5BITS));
            sb.append(charSet.forDigit((value[ind] << 1 | u(value[++ind]) >>> 7) & MASK_5BITS));
            sb.append(charSet.forDigit(u(value[ind]) >>> 2 & MASK_5BITS));
            sb.append(charSet.forDigit(value[ind] << 3 & MASK_5BITS));
        }
        return sb.toString();
    }
    
    public static byte[] decode(String value) {
        return decode(value, crockfordCharSet);
    }
    public static byte[] decodeRFC(String value) {
        return decode(value, rfcCharSet);
    }
    public static byte[] decodeRFCHex(String value) {
        return decode(value, rfcHexCharSet);
    }
    public static byte[] decodeCrockford(String value) {
        return decode(value, crockfordCharSet);
    }
    public static byte[] decode(String encoded, CharacterMap charSet) {
        final ByteArrayOutputStream bb = new ByteArrayOutputStream();
        final char[] digits = encoded.toUpperCase().toCharArray();
        final int remainder = digits.length % 8;
        
        for (int i = 0; i < digits.length - remainder; i += 8) {
            byte a = (byte)charSet.digitFor(digits[i]);
            byte b = (byte)charSet.digitFor(digits[i+1]);
            byte c = (byte)charSet.digitFor(digits[i+2]);
            byte d = (byte)charSet.digitFor(digits[i+3]);
            byte e = (byte)charSet.digitFor(digits[i+4]);
            byte f = (byte)charSet.digitFor(digits[i+5]);
            byte g = (byte)charSet.digitFor(digits[i+6]);
            byte h = (byte)charSet.digitFor(digits[i+7]);
            bb.write( (byte)(a << 3 | b >>> 2) );
            bb.write( (byte)(b << 6 | c << 1 | d >>> 4) );
            bb.write( (byte)(d << 4 | e >>> 1 ));
            bb.write( (byte)(e << 7 | f << 2 | g >>> 3 ));
            bb.write( (byte)(g << 5 | h ));
        }
        int ind = digits.length - remainder;
        if (remainder == 2) {
            byte a = (byte)charSet.digitFor(digits[ind]);
            byte b = (byte)charSet.digitFor(digits[ind+1]);
            bb.write( (byte)(a << 3 | b >>> 2) );
        }
        else if (remainder == 4) {
            byte a = (byte)charSet.digitFor(digits[ind]);
            byte b = (byte)charSet.digitFor(digits[ind+1]);
            byte c = (byte)charSet.digitFor(digits[ind+2]);
            byte d = (byte)charSet.digitFor(digits[ind+3]);
            bb.write( (byte)(a << 3 | b >>> 2) );
            bb.write( (byte)(b << 6 | c << 1 | d >>> 4) );
        }
        else if (remainder == 5) {
            byte a = (byte)charSet.digitFor(digits[ind]);
            byte b = (byte)charSet.digitFor(digits[ind+1]);
            byte c = (byte)charSet.digitFor(digits[ind+2]);
            byte d = (byte)charSet.digitFor(digits[ind+3]);
            byte e = (byte)charSet.digitFor(digits[ind+4]);
            bb.write( (byte)(a << 3 | b >>> 2) );
            bb.write( (byte)(b << 6 | c << 1 | d >>> 4) );
            bb.write( (byte)(d << 4 | e >>> 1 ));
        }
        else if (remainder == 7) {
            byte a = (byte)charSet.digitFor(digits[ind]);
            byte b = (byte)charSet.digitFor(digits[ind+1]);
            byte c = (byte)charSet.digitFor(digits[ind+2]);
            byte d = (byte)charSet.digitFor(digits[ind+3]);
            byte e = (byte)charSet.digitFor(digits[ind+4]);
            byte f = (byte)charSet.digitFor(digits[ind+5]);
            byte g = (byte)charSet.digitFor(digits[ind+6]);
            bb.write( (byte)(a << 3 | b >>> 2) );
            bb.write( (byte)(b << 6 | c << 1 | d >>> 4) );
            bb.write( (byte)(d << 4 | e >>> 1 ));
            bb.write( (byte)(e << 7 | f << 2 | g >>> 3 ));
        }
        return bb.toByteArray();
    }
    
    public static interface CharacterMap {
        public char forDigit(int digit);
        public int digitFor(char c);
    }
    
    /**
     * Douglas Crockford's Base 32 alphabet {@link http://www.crockford.com/wrmg/base32.html}. This
     * alphabet treats I and L as 1, O as 0 and does not contain the letter U to prevent accidental
     * obscenities.
     * 
     * @author jhite
     *
     */
    public static class CrockfordCharacterMap implements CharacterMap {
        private static char[] ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();
        private static Map<Character, Integer> DIGITS = new HashMap<>();
        static {
            for (int i=0; i < ALPHABET.length; i++) {
                DIGITS.put(ALPHABET[i], i);
            }
            DIGITS.put('O', 0);
            DIGITS.put('I', 1);
            DIGITS.put('L', 1);
        }

        public char forDigit(int digit) {
            return ALPHABET[digit];
        }

        public int digitFor(char c) {
            return DIGITS.get(c);
        }
    }

    public static class RfcCharacterMap implements CharacterMap {
        private static char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        private static Map<Character, Integer> DIGITS = new HashMap<>();
        static {
            for (int i=0; i < ALPHABET.length; i++) {
                DIGITS.put(ALPHABET[i], i);
            }
        }

        public char forDigit(int digit) {
            return ALPHABET[digit];
        }

        public int digitFor(char c) {
            return DIGITS.get(c);
        }
    }

    public static class RfcExtendedHexCharacterMap implements CharacterMap {
        private static char[] ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV".toCharArray();
        private static Map<Character, Integer> DIGITS = new HashMap<>();
        static {
            for (int i=0; i < ALPHABET.length; i++) {
                DIGITS.put(ALPHABET[i], i);
            }
        }

        public char forDigit(int digit) {
            return ALPHABET[digit];
        }

        public int digitFor(char c) {
            return DIGITS.get(c);
        }
    }
}