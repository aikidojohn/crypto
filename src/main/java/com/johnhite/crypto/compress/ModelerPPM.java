package com.johnhite.crypto.compress;

import java.util.Iterator;
import java.util.Map;

public class ModelerPPM implements Modeler {
    @Override
    public boolean hasNext() {
        return false;
    }

    @Override
    public ArithmeticCoder.Symbol next() {
        return null;
    }

    @Override
    public Map.Entry<Byte, ArithmeticCoder.Symbol> getEntryFromCount(int count) {
        return null;
    }

    @Override
    public int getBytesProcessed() {
        return 0;
    }

    @Override
    public int getBytesOutput() {
        return 0;
    }

    @Override
    public Iterator<ArithmeticCoder.Symbol> iterator() {
        return null;
    }
}
