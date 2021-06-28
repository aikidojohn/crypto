package com.johnhite.crypto.kms;

import java.security.SecureRandom;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class ManagedKeySet<K> {
    private final Map<String, ManagedKey<K>> keySet = new HashMap<>();
    private final SecureRandom random = new SecureRandom();

    public ManagedKeySet() {
    }

    public ManagedKey<K> getKey(String id) {
        return keySet.get(id);
    }

    public void addKey(ManagedKey<K> key) {
        this.keySet.put(key.getId(), key);
    }

    public int size() {
        return this.keySet.size();
    }

    public Optional<ManagedKey<K>> chooseKey() {
        final long now = System.currentTimeMillis()/1000;
        List<ManagedKey<K>> keys = keySet.entrySet().stream()
                .map(Map.Entry::getValue).filter( k -> k.getNotBefore() + k.getOup() < now)
                .collect(Collectors.toList());
        if (keys.size() == 0) return Optional.empty();

        return Optional.of(keys.get(random.nextInt(keys.size())));
    }
}
