package com.johnhite.crypto.kms;

public class ManagedKey<K> {
    private final K key;
    private final String id;
    private final String algorithm;
    private final long notBefore;
    private final long oup;
    private final long rup;

    private ManagedKey(K key, String id, String algorithm, long notBefore, long oup, long rup) {
        this.key = key;
        this.id = id;
        this.algorithm = algorithm;
        this.notBefore = notBefore;
        this.oup = oup;
        this.rup = rup;
    }

    public static <K> Builder<K> builder() {
        return new Builder<K>();
    }

    public K getKey() {
        return key;
    }

    public String getId() {
        return id;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public long getNotBefore() {
        return notBefore;
    }

    public long getOup() {
        return oup;
    }

    public long getRup() {
        return rup;
    }

    public static class Builder<K> {
        private K key;
        private String id;
        private String algorithm;
        private long notBefore;
        private long oup;
        private long rup;

        public ManagedKey<K> build() {
            return new ManagedKey<>(key, id, algorithm, notBefore, oup, rup);
        }
        public Builder<K> setKey(K key) {
            this.key = key;
            return this;
        }

        public Builder<K> setId(String id) {
            this.id = id;
            return this;
        }

        public Builder<K> setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder<K> setNotBefore(long notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        public Builder<K> setOup(long oup) {
            this.oup = oup;
            return this;
        }

        public Builder<K> setRup(long rup) {
            this.rup = rup;
            return this;
        }
    }
}
