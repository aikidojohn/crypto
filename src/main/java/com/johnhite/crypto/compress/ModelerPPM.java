package com.johnhite.crypto.compress;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

public class ModelerPPM implements Modeler {
    private Context baseContext;
    private Context currentContext;
    private InputStream data;
    private byte currentByte;
    private boolean readFirstByte = false;
    public static final ArithmeticCoder.Symbol ESCAPE = new ArithmeticCoder.Symbol(0, 1,256);

    public ModelerPPM(InputStream in) {
        this.data = in;
    }

    @Override
    public boolean hasNext() {
        return false;
    }

    @Override
    public ArithmeticCoder.Symbol next() {
        try {
            if (!readFirstByte) {
                currentByte = (byte)data.read();
            }

            if (currentContext.inc(currentByte)) {
                return ESCAPE;
            }
            ArithmeticCoder.Symbol symbol = currentContext.getSymbol(currentByte);
            currentContext = currentContext.nextContext(currentByte);
            currentByte = (byte)data.read();
            return symbol;
        }catch (IOException e) {
            throw new RuntimeException(e);
        }
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
    private static class Stats {
        public int count;
        public int low;
        public Context next;
        public Stats nextStat;
    }
    private static class Context {
        public static final int MAX_ORDER = 3;
        public Context previous;
        public Map<Byte, Stats> stats = new HashMap<>();
        private Stats head;
        private Stats tail;
        public final int order;
        public int totalCount = 0;

        public Context() {
            order = 0;
        }
        public Context(Context previous) {
            order = previous.order + 1;
        }
        public Context nextContext(byte b) {
            //TODO if there is no next context - find the next highest order context in the tree
            if (order == MAX_ORDER) {
                return previous.get(b).next;
            }
            return stats.get(b).next;
        }
        public Stats get(byte b) {
            return stats.get(b);
        }
        public ArithmeticCoder.Symbol getSymbol(byte b) {
            Stats stats = get(b);
            int low = stats.low;
            int high = stats.low + stats.count;
            int scale = totalCount;
            return new ArithmeticCoder.Symbol(low, high, scale);
        }

        public void add(byte b) {
            Stats s = new Stats();
            s.count = 1;
            s.low = totalCount + 1;
            if (order <= MAX_ORDER) {
                s.next = new Context(this);
            }
            if (head == null) {
                head = s;
                tail = s;
            }
            tail.nextStat = s;
            tail = s;
            stats.put((byte)b, s);
            totalCount++;
        }

        public boolean inc(byte b) {
            Stats s = stats.get(b);
            if (s == null) {
                add(b);
                return true;
            }
            totalCount++;
            s.count += 1;
            //increment low counters for all following stats.
            s = s.nextStat;
            while (s != null) {
                s.low += 1;
                s = s.nextStat;
            }
            return false;
        }
    }
}
