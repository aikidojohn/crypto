package com.johnhite.crypto.demo;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class TimingAttack {

    public static boolean verify(String key) {
        if ("pja24".equals(key)) {
            return true;
        }
        return false;
    }

    private static SecureRandom rand = new SecureRandom();

    public static void shuffle(char[] array) {
        for (int i = 0; i < array.length/2; i++) {
            int index = rand.nextInt(array.length);
            char x = array[i];
            array[i] = array[index];
            array[index] = x;
        }
    }

    public static void main(String... args) throws InterruptedException {
        char[] alpha = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
        int samples = 2;
        /*for (int n=0; n < 10; n++) {

        }*/
        verify("&0000");
        //find length
        Map<Integer, Long> lenTimes = new HashMap<>();
        StringBuilder sb = new StringBuilder();
        for (int i =0; i < 10; i++) {
            sb.append("0");
            String s = sb.toString();
            long start = System.nanoTime();
            for (int j=0; j < 100000; j++) {
                verify(s);
            }
            long end = System.nanoTime();
            if (!lenTimes.containsKey(i)) {
                lenTimes.put(i, 0L);
            }
            lenTimes.put(i, lenTimes.get(i) + (end - start));
        }
        List<Map.Entry<Integer, Long>> sortedLen = lenTimes.entrySet().stream()
                .sorted( (a, b) -> a.getValue() >= b.getValue() ? -1 : 1 )
                .collect(Collectors.toList());
        for (Map.Entry<Integer, Long> e : sortedLen) {
            System.out.println("" + e.getKey() + " : " + e.getValue());
        }

        Map<Character, Long> timing = new HashMap<>();
        for (int i=0; i < 100; i++) {
            for (char a : alpha) {
                String s = new StringBuilder().append("pja").append(a).append("0").toString();
                long start = System.nanoTime();
                for (int k=0; k < 100000; k++) {
                    verify(s);
                }
                long end = System.nanoTime();
                if (!timing.containsKey(a)) {
                    timing.put(a, 0L);
                }
                timing.put(a, timing.get(a) + (end - start));
                //System.out.println(s + " : " + (end - start));
            }
            shuffle(alpha);
        }

        /*Arrays.sort(alpha);
        for (char a : alpha) {
            StringBuilder sb = new StringBuilder();
            sb.append(a);
            sb.append(" : ");
            sb.append(timing.get(a));
            System.out.println(sb.toString());
        }*/
        List<Map.Entry<Character, Long>> sorted = timing.entrySet().stream()
                .sorted( (a, b) -> a.getValue() >= b.getValue() ? -1 : 1 )
                .collect(Collectors.toList());
        for (Map.Entry<Character, Long> e : sorted) {
            System.out.println(e.getKey() + " : " + e.getValue());
        }
    }
}
