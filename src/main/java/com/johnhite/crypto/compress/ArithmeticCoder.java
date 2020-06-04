package com.johnhite.crypto.compress;
import com.johnhite.crypto.salsa20.ChaChaInputStream;
import com.johnhite.crypto.salsa20.ChaChaOutputStream;
import org.apache.commons.codec.binary.Hex;

import java.io.*;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

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
        long range = (long)(high - low)+1;
        high = (int)((long)low + (range * s.highCount) / (long)s.scale - 1L);
        low = (int)((long)low + (range * s.lowCount) / (long)s.scale);
        //System.out.println("encoding symbol " + s);

        for(;;) {
            //System.out.println("\tlow = " + low + " high = " + high);
            if ((high & 0x8000) == (low & 0x8000)) {
                stream.outputBit(high  & 0x8000);
                //System.out.println("\toutput bit: " + (high & 0x8000));
                while (underflowBits > 0) {
                    stream.outputBit(~high & 0x8000);
                    //System.out.println("\toutput underflow bit: " + (~high & 0x8000));
                    underflowBits--;
                }
            }
            else if ((low & 0x4000) == 0x4000 && (high & 0x4000) == 0) { // (low & 0x4000) == 0x4000 && (high & 0x4000) == 0 ??? //(low & 0x4000)  != (high & 0x4000)
                underflowBits++;
                low &= 0x3FFF;
                high |= 0x4000;
                //System.out.println("\tunderflow. low = " + low + " high = " + high);
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
        //System.out.println("\toutput final bit: " + (low & 0x4000));
        while(underflowBits > 0) {
            stream.outputBit(~low & 0x4000);
           // System.out.println("\toutput final underflow bit: " + (~low & 0x4000));
            underflowBits--;
        }
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

    public int getCurrentCount(Symbol s) {
        long range = (long)(high - low) +1;
        int count = (int)(((long)(code - low +1)*(long)s.scale - 1)/ range);
        if (count < 0) {
            System.out.println("on noes!");
        }
        return count;
    }

    public void removeSymbolFromStream(Symbol s, BitIO stream) throws IOException {
        long range = (long)(high - low) + 1;
        high = (int)((long)low + (range * s.highCount) / (long)s.scale -1);
        low = (int)((long)low + (range * s.lowCount) / (long)s.scale);
        for (;;) {
            if ((high & 0x8000) == (low & 0x8000)) {
            }
            else if ( (low & 0x4000) == 0x4000 && (high & 0x4000) == 0) {
                code ^= 0x4000;
                low &= 0x3FFF;
                high |= 0x4000;
            }
            else return;

            low <<= 1; //shift in a 0 on the low count
            high <<= 1;
            high |= 1; //shift in a 1 on the high count
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
        //testBillGates();
        testWiki2();
    }

    private static void testWiki2() throws IOException {
        File compOut =new File("e:\\projects\\crypto\\target\\compressed.acc");
        File expOut = new File("e:\\projects\\crypto\\target\\expanded.mhtml");
        if (compOut.exists()) compOut.delete();
        if (expOut.exists()) expOut.delete();

        Modeler modeler = new Modeler8B("e:\\projects\\crypto\\data-compression.mhtml");

        //Set up compression and output

        byte[] key = new byte[32];
        byte[] nonce = new byte[8];

        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream("e:\\projects\\crypto\\target\\compressed.acc"));
        BitIO outBits = new BitIO(new ChaChaOutputStream(out, key, nonce));
        ArithmeticCoder coder = new ArithmeticCoder();
        coder.initializeEncoder();

        for (Symbol s : modeler) {
            coder.encodeSymbol(s, outBits);
        }

        coder.flushEncoder(outBits);
        outBits.flush();
        out.flush();
        out.close();

        //expand
        FileInputStream in = new FileInputStream("e:\\projects\\crypto\\target\\compressed.acc");
        BitIO inStream = new BitIO(new ChaChaInputStream(in, key, nonce));
        coder = new ArithmeticCoder();
        coder.initializeDecoder(inStream);
        final Symbol symScale = modeler.getEntryFromCount(0).getValue();

        BufferedOutputStream expanded = new BufferedOutputStream(new FileOutputStream("e:\\projects\\crypto\\target\\expanded.mhtml"));
        int expandedBytes = modeler.getBytesProcessed();
        for (int i=0; i< expandedBytes; i++) {
            int count = coder.getCurrentCount(symScale);
            Map.Entry<Byte, ArithmeticCoder.Symbol> entry = modeler.getEntryFromCount(count);
            coder.removeSymbolFromStream(entry.getValue(), inStream);
            int low = entry.getKey();

            /*count = coder.getCurrentCount(symScale);
            entry = modeler.getEntryFromCount(count);
            coder.removeSymbolFromStream(entry.getValue(), inStream);
            int high = entry.getKey();

            expanded.write((byte)((high << 4) | low));*/
            expanded.write(low);
        }
        expanded.flush();
        expanded.close();
    }

    private static void testWiki() throws IOException {
        File f = new File("e:\\projects\\crypto\\data-compression.mhtml");
        FileInputStream fin = new FileInputStream(f);
        byte[] buffer = new byte[8196];
        Map<Byte, Integer> stats = new HashMap<>();
        int count = 0;
        int read = 0;
        while ( (read = fin.read(buffer)) > 0) {
            count += read;
            for (int i= 0; i< read; i++) {
                byte bl = (byte)(buffer[i] & 0x0F);
                byte bh = (byte)((buffer[i] >>> 4) & 0x0F);
                stats.put(bl, stats.getOrDefault(bl, 0) +1);
                stats.put(bh, stats.getOrDefault(bh, 0) +1);
                //stats.put(buffer[i], stats.getOrDefault(buffer[i], 0) + 1);
            }
        }
        fin.close();
        final Map<Byte, Symbol> symbolTable = new HashMap<>();
        final int finalCount = count *2;
        stats.forEach((k,v) -> {
            System.out.println(k + "," + v + "," + ((double)v/(double)finalCount));
        });
        int lastValue = 0;
        for (Map.Entry<Byte, Integer> e : stats.entrySet()) {
            double prob = (double)e.getValue()/(double)finalCount;
            int highValue = lastValue +  (int)Math.floor(10000 * prob);
            symbolTable.put(e.getKey(), new Symbol(lastValue, highValue, 9991));
            lastValue = highValue;
        }

        //Set up compression and output
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream("e:\\projects\\crypto\\data-compression.mhtml.acc"));
        BitIO outBits = new BitIO(out);
        ArithmeticCoder coder = new ArithmeticCoder();
        coder.initializeEncoder();

        //generate symbol stream
        fin = new FileInputStream(f);
        read = 0;
        while ( (read = fin.read(buffer)) > 0) {
            for (int i= 0; i< read; i++) {
                byte bl = (byte)(buffer[i] & 0x0F);
                byte bh = (byte)((buffer[i] >>> 4) & 0x0F);
                coder.encodeSymbol(symbolTable.get(bl), outBits);
                coder.encodeSymbol(symbolTable.get(bh), outBits);
            }
        }
        coder.flushEncoder(outBits);
        outBits.flush();
        out.flush();
        out.close();
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
