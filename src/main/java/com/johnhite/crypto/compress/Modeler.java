package com.johnhite.crypto.compress;

import java.util.Map;

public interface Modeler extends Iterable<ArithmeticCoder.Symbol> {
    boolean hasNext();
    ArithmeticCoder.Symbol next();
    Map.Entry<Byte, ArithmeticCoder.Symbol> getEntryFromCount(int count);
    int getBytesProcessed();
    int getBytesOutput();
}
