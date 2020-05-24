package com.johnhite.crypto.compress;
import org.apache.commons.codec.binary.Hex;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Based on https://marknelson.us/posts/1991/02/01/arithmetic-coding-statistical-modeling-data-compression.html
 */
public class ArithmeticCoder {
    private int code = 0;
    private int low = 0;
    private int high = 0xFFFF;
    private long underflowBits;

    private ArithmeticCoder() {

    }

    public void initializeEncoder() {
        code =0;
        low = 0;
        high = 0xFFFF;
    }

    public void encodeSymbol(Symbol s, BitIO stream) throws IOException {
        long range;
        range = (long)(high - low)+1;
        high = (int)(low + (range * s.highCount) / s.scale -1);
        low = (int)(low + (range * s.lowCount) / s.scale);
        System.out.println("encoding symbol " + s);

        for(;;) {
            System.out.println("\tlow = " + low + " high = " + high);
            if ((high & 0x8000) == (low & 0x8000)) {
                stream.outputBit(high & 0x8000);
                System.out.println("\toutput bit: " + (high & 0x8000));
                while (underflowBits > 0) {
                    stream.outputBit(~high & 0x8000);
                    System.out.println("\toutput underflow bit: " + (~high & 0x8000));
                    underflowBits--;
                }
            }
            else if ((low & 0x4000) == 0x4000 && (high & 0x4000) == 0) { // (low & 0x4000) == 0x4000 && (high & 0x4000) == 0 ??? //(low & 0x4000)  != (high & 0x4000)
                underflowBits++;
                low &= 0x3FFF;
                high |= 0x4000;
                System.out.println("\tunderflow. low = " + low + " high = " + high);
            }
            else return;
            low <<= 1;
            high <<= 1;
            high |= 1;
            low &= 0xFFFF;
            high &= 0xFFFF;
        }
    }

    public void flushEncoder(BitIO stream) throws IOException {
        stream.outputBit(low & 0x4000);
        System.out.println("\toutput final bit: " + (low & 0x4000));
        while(underflowBits > 0) {
            stream.outputBit(~low & 0x4000);
            System.out.println("\toutput final underflow bit: " + (~low & 0x4000));
            underflowBits--;
        }
    }

    public int getCurrentCount(Symbol s) {
        long range = (long)(high - low) +1;
        int count = (int)(((code - low +1)*s.scale - 1)/ range);
        return count;
    }

    public void initializeDecoder(BitIO stream) throws IOException {
        code = 0;
        for (int i = 0; i < 16; i++) {
            code <<= 1;
            code += stream.inputBit();
        }
        low = 0;
        high = 0xffff;
    }

    public void removeSymbolFromStream(Symbol s, BitIO stream) throws IOException {
        long range = (long)(high - low) + 1;
        high = (int)(low + (range * s.highCount) / s.scale -1);
        low = (int)(low + (range * s.lowCount) / s.scale);
        for (;;) {
            if ((high & 0x8000) == (low & 0x8000)) {
            }
            else if ( (low & 0x4000) == 0x4000 && (high & 0x4000) == 0) {
                code ^= 0x4000;
                low &= 0x3FFF;
                high |= 0x4000;
            }
            else return;

            low <<= 1;
            high <<= 1;
            high |= 1;
            low &= 0xFFFF;
            high &= 0xFFFF;
            code <<= 1;
            code += stream.inputBit();
            code &= 0xFFFF;
        }
    }



    public static final class Symbol {
        public final int lowCount;
        public final int highCount;
        public final int scale;

        public Symbol(int lowCount, int highCount, int scale) {
            this.lowCount = lowCount;
            this.highCount = highCount;
            this.scale = scale;
        }

        @Override
        public String toString() {
            return "Symbol{" +
                    "lowCount=" + lowCount +
                    ", highCount=" + highCount +
                    ", scale=" + scale +
                    '}';
        }
    }

    public static final class BitIO {
        private final InputStream in;
        private final OutputStream out;
        private byte currentByte;
        int mask;

        int bitsLeft =0;
        int bytesLeft =1;
        int pastEof = 0;

        private BitIO(InputStream in) {
            this.in = in;
            this.out = null;
        }
        private BitIO(OutputStream out) {
            this.in = null;
            this.out = out;
            mask = 0x80;
            currentByte = 0;
        }

        public void outputBit(int bit) throws IOException {
            if (bit != 0) {
                currentByte |= mask;
            }
            mask >>= 1;
            if (mask == 0) {
                mask = 0x80;
                out.write((int)currentByte);
                currentByte = 0;
            }
        }

        public void flush() throws IOException {
            if (mask != 0x80)
                out.write((int)currentByte);
        }

        public int inputBit() throws IOException {
            if (bitsLeft == 0) {
                bitsLeft = 8;
                currentByte = (byte)in.read();
            }
            bitsLeft--;
            return (currentByte >> bitsLeft) & 1;
        }

    }
    public static void main(String... args) throws IOException {
        int h = 0xBFFF;
        int l = 0x7FFF;

        System.out.println(h & 0x4000);
        System.out.println(l & 0x4000);


        ByteArrayInputStream in = new ByteArrayInputStream(new byte[] {(byte)0x0F, (byte)0xA0});
        BitIO inbits = new BitIO(in);
        for (int i= 0; i< 16; i++) {
            System.out.print(inbits.inputBit());
            System.out.print(" ");
        }
        System.out.println();
        for (int i= 0; i< 16; i++) {
            System.out.print(inbits.inputBit());
            System.out.print(" ");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BitIO outBits = new BitIO(out);
        for (int i=0; i < 14; i++) {
            outBits.outputBit(i %2);
        }
        outBits.flush();
        System.out.println();
        System.out.println(Hex.encodeHexString(out.toByteArray()));
        testBillGates();
    }

    private static void testBillGates() throws IOException {
        Map<Character, Symbol> symbolMap = new HashMap<>();
        symbolMap.put('B', new Symbol(0,1,11));
        symbolMap.put('I', new Symbol(1,2,11));
        symbolMap.put('L', new Symbol(2,4,11));
        symbolMap.put(' ', new Symbol(4,5,11));
        symbolMap.put('G', new Symbol(5,6,11));
        symbolMap.put('A', new Symbol(6,7,11));
        symbolMap.put('T', new Symbol(7,8,11));
        symbolMap.put('E', new Symbol(8,9,11));
        symbolMap.put('S', new Symbol(9,10,11));
        symbolMap.put('\0', new Symbol(10,11,11));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        BitIO outStream = new BitIO(out);
        ArithmeticCoder coder = new ArithmeticCoder();
        coder.initializeEncoder();
        Symbol[] inputSymbols = createSymbolArray(symbolMap, "BILL GATES");
        for(Symbol s : inputSymbols) {
            coder.encodeSymbol(s, outStream);
        }
        coder.flushEncoder(outStream);
        outStream.flush();
        byte[] compressed = out.toByteArray();
        System.out.println(Hex.encodeHexString(compressed));

        ByteArrayInputStream in = new ByteArrayInputStream(compressed);
        BitIO inStream = new BitIO(in);
        coder = new ArithmeticCoder();
        coder.initializeDecoder(inStream);
        final Symbol symScale = new Symbol(-1,-1, 11);

        StringBuilder sb = new StringBuilder();
        for (;;) {
            int count = coder.getCurrentCount(symScale);
            Map.Entry<Character, Symbol> entry = getEntryFromCount(count, symbolMap);
            if (entry.getKey().charValue() == '\0') {
                break;
            }
            coder.removeSymbolFromStream(entry.getValue(), inStream);
            sb.append(entry.getKey());
            System.out.print(entry.getKey());
        }
        System.out.println();
        System.out.println(sb.toString());
    }

    private static Map.Entry<Character, Symbol> getEntryFromCount(int count, Map<Character, Symbol> symbolMap)
    {
        for (Map.Entry<Character, Symbol> entry : symbolMap.entrySet()) {
            Symbol s = entry.getValue();
            if (count >= s.lowCount && count < s.highCount) {
                return entry;
            }
        }
        throw new RuntimeException("Failed to decode character. Count = " + count);
    }

    private static Symbol[] createSymbolArray(Map<Character,Symbol> symbolMap, String symbolString) {
        char[] symbolChars = symbolString.toCharArray();
        Symbol[] symbols = new Symbol[symbolChars.length+1];
        for (int i=0; i< symbolChars.length; i++) {
            symbols[i] = symbolMap.get(symbolChars[i]);
        }
        symbols[symbols.length-1] = symbolMap.get('\0');
        return symbols;
    }
}
