package com.johnhite.crypto.compress;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Modeler4B implements Modeler, Iterator<ArithmeticCoder.Symbol> {
    private String file;
    private InputStream data;
    private byte[] buffer = new byte[8196];
    private int bufferCount = 0;

    private Map<Byte, ArithmeticCoder.Symbol> symbolTable = new HashMap<>();
    private int symbolCount;
    private int currentSymbol;

    public Modeler4B(String file) throws IOException {
        this.file = file;
        FileInputStream data = new FileInputStream(file);
        Map<Byte, Integer> stats = new HashMap<>();
        int count = 0;
        int read = 0;
        while ( (read = data.read(buffer)) > 0) {
            count += read;
            for (int i= 0; i< read; i++) {
                byte bl = (byte)(buffer[i] & 0x0F);
                byte bh = (byte)((buffer[i] >>> 4) & 0x0F);
                stats.put(bl, stats.getOrDefault(bl, 0) +1);
                stats.put(bh, stats.getOrDefault(bh, 0) +1);
                //stats.put(buffer[i], stats.getOrDefault(buffer[i], 0) + 1);
            }
        }
        data.close();

        symbolCount = count *2;
        stats.forEach((k,v) -> {
            System.out.println(k + "," + v + "," + ((double)v/(double)symbolCount));
        });
        int lastValue = 0;
        for (Map.Entry<Byte, Integer> e : stats.entrySet()) {
            double prob = (double)e.getValue()/(double)symbolCount;
            int highValue = lastValue +  (int)Math.floor(16384 * prob);
            symbolTable.put(e.getKey(), new ArithmeticCoder.Symbol(lastValue, highValue, 16384));
            lastValue = highValue;
        }
    }

    private void openFile() throws IOException {
        data = new FileInputStream(file);
        currentSymbol = 0;
    }

    private int fillBuffer() throws IOException {
        return data.read(buffer);
    }

    @Override
    public boolean hasNext() {
        return currentSymbol != symbolCount;
    }

    @Override
    public ArithmeticCoder.Symbol next() {
        try {
            if (data == null) {
                openFile();
            }
            int symbolIndex = currentSymbol % (buffer.length *2);
            if (symbolIndex == 0) {
                bufferCount += data.read(buffer);
            }
            currentSymbol++;
            if (symbolIndex % 2 == 0){
                byte bl = (byte)(buffer[symbolIndex/2] & 0x0F);
                return symbolTable.get(bl);
            }
            byte bh = (byte)((buffer[symbolIndex/2] >>> 4) & 0x0F);
            return symbolTable.get(bh);
        }
        catch (IOException e) {
            throw new RuntimeException("Failed to read next symbol", e);
        }
    }

    @Override
    public Iterator<ArithmeticCoder.Symbol> iterator() {
        return this;
    }

    public Map.Entry<Byte, ArithmeticCoder.Symbol> getEntryFromCount(int count) {
        for (Map.Entry<Byte, ArithmeticCoder.Symbol> entry : symbolTable.entrySet()) {
            if (count >= entry.getValue().lowCount && count < entry.getValue().highCount) {
                return entry;
            }
        }
        throw new RuntimeException("Could not decode symbol. count = " + count);
    }
    public int getBytesProcessed() {
        return bufferCount;
    }

    public int getBytesOutput() {
        return 0; //TODO
    }
}
