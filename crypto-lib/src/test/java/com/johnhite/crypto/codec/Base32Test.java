package com.johnhite.crypto.codec;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

public class Base32Test {

    @Test
    public void testBase32RFCVectors() {
        assertEquals("", Base32.encodeRFC("".getBytes()));
        assertEquals("MY", Base32.encodeRFC("f".getBytes()));
        assertEquals("MZXQ", Base32.encodeRFC("fo".getBytes()));
        assertEquals("MZXW6", Base32.encodeRFC("foo".getBytes()));
        assertEquals("MZXW6YQ", Base32.encodeRFC("foob".getBytes()));
        assertEquals("MZXW6YTB", Base32.encodeRFC("fooba".getBytes()));
        assertEquals("MZXW6YTBOI", Base32.encodeRFC("foobar".getBytes()));

        assertArrayEquals("f".getBytes(), Base32.decodeRFC("MY"));
        assertArrayEquals("fo".getBytes(), Base32.decodeRFC("MZXQ"));
        assertArrayEquals("foo".getBytes(), Base32.decodeRFC("MZXW6"));
        assertArrayEquals("foob".getBytes(), Base32.decodeRFC("MZXW6YQ"));
        assertArrayEquals("fooba".getBytes(), Base32.decodeRFC("MZXW6YTB"));
        assertArrayEquals("foobar".getBytes(), Base32.decodeRFC("MZXW6YTBOI"));
    }
    
    @Test
    public void testBase32RFCHexVectors() {
        assertEquals("", Base32.encodeRFCHex("".getBytes()));
        assertEquals("CO", Base32.encodeRFCHex("f".getBytes()));
        assertEquals("CPNG", Base32.encodeRFCHex("fo".getBytes()));
        assertEquals("CPNMU", Base32.encodeRFCHex("foo".getBytes()));
        assertEquals("CPNMUOG", Base32.encodeRFCHex("foob".getBytes()));
        assertEquals("CPNMUOJ1", Base32.encodeRFCHex("fooba".getBytes()));
        assertEquals("CPNMUOJ1E8", Base32.encodeRFCHex("foobar".getBytes()));

        assertArrayEquals("f".getBytes(), Base32.decodeRFCHex("CO"));
        assertArrayEquals("fo".getBytes(), Base32.decodeRFCHex("CPNG"));
        assertArrayEquals("foo".getBytes(), Base32.decodeRFCHex("CPNMU"));
        assertArrayEquals("foob".getBytes(), Base32.decodeRFCHex("CPNMUOG"));
        assertArrayEquals("fooba".getBytes(), Base32.decodeRFCHex("CPNMUOJ1"));
        assertArrayEquals("foobar".getBytes(), Base32.decodeRFCHex("CPNMUOJ1E8"));
    }
    
    @Test
    public void testBase32CrockfordVectors() {
        assertEquals("", Base32.encodeCrockford("".getBytes()));
        assertEquals("CR", Base32.encodeCrockford("f".getBytes()));
        assertEquals("CSQG", Base32.encodeCrockford("fo".getBytes()));
        assertEquals("CSQPY", Base32.encodeCrockford("foo".getBytes()));
        assertEquals("CSQPYRG", Base32.encodeCrockford("foob".getBytes()));
        assertEquals("CSQPYRK1", Base32.encodeCrockford("fooba".getBytes()));
        assertEquals("CSQPYRK1E8", Base32.encodeCrockford("foobar".getBytes()));

        assertArrayEquals("f".getBytes(), Base32.decodeCrockford("CR"));
        assertArrayEquals("fo".getBytes(), Base32.decodeCrockford("CSQG"));
        assertArrayEquals("foo".getBytes(), Base32.decodeCrockford("CSQPY"));
        assertArrayEquals("foob".getBytes(), Base32.decodeCrockford("CSQPYRG"));
        assertArrayEquals("fooba".getBytes(), Base32.decodeCrockford("CSQPYRK1"));
        assertArrayEquals("foobar".getBytes(), Base32.decodeCrockford("CSQPYRK1E8"));
    }

    @Test
    public void testCrockfordSubstitutions() {
        String valid = "H1F0";
        byte[] expected = Base32.decode(valid);
        assertArrayEquals(expected, Base32.decodeCrockford("HIF0"));
        assertArrayEquals(expected, Base32.decodeCrockford("HiF0"));
        assertArrayEquals(expected, Base32.decodeCrockford("HLF0"));
        assertArrayEquals(expected, Base32.decodeCrockford("HlF0"));
        assertArrayEquals(expected, Base32.decodeCrockford("H1FO"));
        assertArrayEquals(expected, Base32.decodeCrockford("H1Fo"));
        assertArrayEquals(expected, Base32.decodeCrockford("HIFO"));
    }

    //@Test
    public void testCompression() {
        Random rand = new Random();
        for (int i=1; i < 20; i++) {
            byte[] test = new byte[i];
            rand.nextBytes(test);
            String encoded16 = Hex.encodeHexString(test);
            String encoded32 = Base32.encodeCrockford(test);
            String encoded64 = Base64.encodeBase64String(test);
            System.out.println("Original = " + i);
            System.out.println("Hex:    " + encoded16);
            System.out.println("Base32: " + encoded32);
            System.out.println("Base64: " + encoded64);
        }
    }
    
    @Test
    public void testRandomLengths() {
        Random rand = new Random();
        for (int i=1; i < 50; i++) {
            byte[] test = new byte[i];
            rand.nextBytes(test);
            String encoded32 = Base32.encodeCrockford(test);
            if (!Arrays.equals(test, Base32.decodeCrockford(encoded32))) {
                System.out.println("Failure case");
                System.out.println("Test Vector   : " + Arrays.toString(test));
                System.out.println("Decoded Vector: " + Arrays.toString(Base32.decodeCrockford(encoded32)));
                fail("Decoding an encoded vector did not produce the original vector.");
            }
        }
    }
    
    @Test
    public void testPerformance() {
        Random rand = new Random();
        final int tests = 100000;
        List<byte[]> testVectors = new ArrayList<>();
        List<String> crap = new ArrayList<String>(tests);
        for (int i=0; i < tests; i++) {
            byte[] test = new byte[16];
            rand.nextBytes(test);
            testVectors.add(test);
        }
        
        long start = System.currentTimeMillis();
        for (int i=0; i < tests; i++) {
            byte[] test = testVectors.get(i);
            String encoded16 = Hex.encodeHexString(test);
            crap.add(encoded16);
        }
        long end = System.currentTimeMillis();
        System.out.println("Base 16: " + (end - start));
        crap.clear();
        
        start = System.currentTimeMillis();
        for (int i=0; i < tests; i++) {
            byte[] test = testVectors.get(i);
            String encoded32 = Base32.encodeCrockford(test);
            crap.add(encoded32);
        }
        end = System.currentTimeMillis();
        System.out.println("Base 32: " + (end - start));
        crap.clear();
        
        org.apache.commons.codec.binary.Base32 commonsBase32 = new org.apache.commons.codec.binary.Base32();
        start = System.currentTimeMillis();
        for (int i=0; i < tests; i++) {
            byte[] test = testVectors.get(i);
            String encoded32 = commonsBase32.encodeAsString(test);
            crap.add(encoded32);
        }
        end = System.currentTimeMillis();
        System.out.println("Apac 32: " + (end - start));
        crap.clear();
        
        start = System.currentTimeMillis();
        for (int i=0; i < tests; i++) {
            byte[] test = testVectors.get(i);
            String encoded64 = Base64.encodeBase64String(test);
            crap.add(encoded64);
        }
        end = System.currentTimeMillis();
        System.out.println("Base 64: " + (end - start));
        crap.clear();
    }
}

