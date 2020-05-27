package com.johnhite.crypto.compress;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Modeler8B implements Modeler, Iterator<ArithmeticCoder.Symbol> {
    private String file;
    private InputStream data;
    private byte[] buffer = new byte[8196];
    private int bufferCount = 0;

    private Map<Byte, ArithmeticCoder.Symbol> symbolTable = new HashMap<>();
    private int symbolCount;
    private int currentSymbol;

    public Modeler8B(String file) throws IOException {
        this.file = file;
        FileInputStream data = new FileInputStream(file);
        Map<Byte, Integer> stats = new HashMap<>();
        int count = 0;
        int read = 0;
        while ( (read = data.read(buffer)) > 0) {
            count += read;
            for (int i= 0; i< read; i++) {
                stats.put(buffer[i], stats.getOrDefault(buffer[i], 0) + 1);
            }
        }
        data.close();

        symbolCount = count;
        stats.forEach((k,v) -> {
            System.out.println(k + "," + v + "," + ((double)v/(double)symbolCount));
        });
        Map<Byte,ArithmeticCoder.Symbol> firstPass = new HashMap<>();
        int lastValue = 0;
        for (Map.Entry<Byte, Integer> e : stats.entrySet()) {
            double prob = (double)e.getValue()/(double)symbolCount;
            int highValue = lastValue +  (int)Math.ceil(16383 * prob);
            firstPass.put(e.getKey(), new ArithmeticCoder.Symbol(lastValue, highValue, 16383));
            lastValue = highValue;
        }
        for (Map.Entry<Byte, ArithmeticCoder.Symbol> entry : firstPass.entrySet()) {
            ArithmeticCoder.Symbol s = new ArithmeticCoder.Symbol(entry.getValue().lowCount, entry.getValue().highCount, lastValue);
            System.out.println(String.valueOf(entry.getKey()) + ", " + s.lowCount + ", " + s.highCount +", " + s.scale);
            symbolTable.put(entry.getKey(), s);
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
            int symbolIndex = currentSymbol % (buffer.length);
            if (symbolIndex == 0) {
                bufferCount += data.read(buffer);
            }
            currentSymbol++;
            return symbolTable.get(buffer[symbolIndex]);
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
}
