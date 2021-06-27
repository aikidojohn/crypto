package com.johnhite.crypto.kms;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class KeyManager {

    private final ManagedKeySet<SecretKey> masterKeys = new ManagedKeySet<>();
    private final ManagedKeySet managedKeys = new ManagedKeySet<>();
    long id =0;

    public KeyManager() throws NoSuchAlgorithmException {
        if (masterKeys.size() == 0) {
            generateMasterKeys(3);
        }
    }

    private String nextId() {
        return String.valueOf(id++);
    }

    private void generateMasterKeys(int numberKeys) throws NoSuchAlgorithmException {
        KeyGenerator g = KeyGenerator.getInstance("AES");
        g.init(256, new SecureRandom());
        long now = System.currentTimeMillis()/1000;
        //long oup = 60 *60 *24 *365 *2; //2 years
        //long rup = 60 *60 *24 *365 *3; //3 years
        long oup = 60;
        long rup = 60 * 5;
        for (int i =0; i < numberKeys; i++) {
            masterKeys.addKey(ManagedKey.<SecretKey>builder()
                    .setKey(g.generateKey())
                    .setId(nextId())
                    .setAlgorithm("AES")
                    .setNotBefore(now)
                    .setOup(oup)
                    .setRup(rup)
                    .build());
        }
    }

    public byte[] encrypt(byte[] data, String keyId, String mode, AlgorithmParameterSpec params) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        ManagedKey k = managedKeys.getKey(keyId);
        Key key = (k.getKey() instanceof SecretKey) ? (SecretKey) k.getKey() : ((KeyPair)k.getKey()).getPublic();
        Cipher c = Cipher.getInstance(k.getAlgorithm() + "/" + mode);
        c.init(Cipher.ENCRYPT_MODE, key, params);
        return c.doFinal(data);
    }

    public byte[] decrypt(byte[] data, String keyId, String mode)  throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        ManagedKey k = managedKeys.getKey(keyId);
        Key key = (k.getKey() instanceof SecretKey) ? (SecretKey) k.getKey() : ((KeyPair)k.getKey()).getPrivate();
        Cipher c = Cipher.getInstance(k.getAlgorithm() + "/" + mode);
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(data);
    }

    public byte[] encrypt(byte[] data, String keyId, String mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        ManagedKey k = managedKeys.getKey(keyId);
        Key key = (k.getKey() instanceof SecretKey) ? (SecretKey) k.getKey() : ((KeyPair)k.getKey()).getPublic();
        Cipher c = Cipher.getInstance(k.getAlgorithm() + "/" + mode);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public byte[] decrypt(byte[] data, String keyId, String mode, AlgorithmParameterSpec params)  throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        ManagedKey k = managedKeys.getKey(keyId);
        Key key = (k.getKey() instanceof SecretKey) ? (SecretKey) k.getKey() : ((KeyPair)k.getKey()).getPrivate();
        Cipher c = Cipher.getInstance(k.getAlgorithm() + "/" + mode);
        c.init(Cipher.DECRYPT_MODE, key, params);
        return c.doFinal(data);
    }

    public byte[] sign(byte[] data, String keyId, String digest) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        ManagedKey k = managedKeys.getKey(keyId);
        if (k.getAlgorithm().toLowerCase().contains("hmac")) {
            Mac mac = Mac.getInstance(k.getAlgorithm());
            mac.init((Key)k.getKey());
            return mac.doFinal(data);
        }
        else if (k.getKey() instanceof KeyPair) {
            Signature s = Signature.getInstance(digest + "with" + (k.getAlgorithm().equalsIgnoreCase("EC") ? "ECDSA" : k.getAlgorithm()));
            s.initSign(((KeyPair)k.getKey()).getPrivate());
            s.update(data);
            return s.sign();
        }
        throw new UnsupportedOperationException("Invalid operation for key type");
    }

    public boolean verify(byte[] data, byte[] signature, String keyId, String digest) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        ManagedKey k = managedKeys.getKey(keyId);
        if (k.getAlgorithm().toLowerCase().contains("hmac")) {
            Mac mac = Mac.getInstance(k.getAlgorithm());
            mac.init((Key)k.getKey());
            byte[] verify = mac.doFinal(data);
            return Arrays.equals(signature, verify);
        }
        else if (k.getKey() instanceof KeyPair) {
            Signature s = Signature.getInstance(digest + "with" + (k.getAlgorithm().equalsIgnoreCase("EC") ? "ECDSA" : k.getAlgorithm()));
            s.initVerify(((KeyPair)k.getKey()).getPublic());
            s.update(data);
            return s.verify(signature);
        }
        throw new UnsupportedOperationException("Invalid operation for key type");
    }

    public byte[] wrap(byte[] data, String keyId) {
        throw new UnsupportedOperationException();
    }

    public byte[] unwrap(byte[] data, String keyId) {
        throw new UnsupportedOperationException();
    }

    public String createKey(String algorithm, AlgorithmParameterSpec params, KeyOps... ops) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyGenerator g = KeyGenerator.getInstance(algorithm);
        g.init(params);
        String id = nextId();
        long now = System.currentTimeMillis()/1000;
        managedKeys.addKey(ManagedKey.<SecretKey>builder()
                .setKey(g.generateKey())
                .setId(id)
                .setAlgorithm(algorithm)
                .setNotBefore(now)
                .setOup(60)
                .setRup(60*3)
                .build());
        return id;
    }

    public String createKey(String algorithm, int keySize, KeyOps... ops) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyGenerator g = KeyGenerator.getInstance(algorithm);
        g.init(keySize);
        String id = nextId();
        long now = System.currentTimeMillis()/1000;
        managedKeys.addKey(ManagedKey.<SecretKey>builder()
                .setKey(g.generateKey())
                .setId(id)
                .setAlgorithm(algorithm)
                .setNotBefore(now)
                .setOup(60)
                .setRup(60*3)
                .build());
        return id;
    }

    public ManagedKey<PublicKey> createKeyPair(String algorithm, AlgorithmParameterSpec params, KeyOps... ops) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        for (KeyOps op : ops) {
            if (op == KeyOps.WRAP_KEY || op == KeyOps.UNWRAP_KEY || op == KeyOps.DERIVE_BITS || op == KeyOps.DERIVE_KEY) {
                throw new UnsupportedOperationException("Invalid operation for key type: " + op.toString());
            }
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm);
        g.initialize(params);
        KeyPair pair = g.generateKeyPair();
        String id = nextId();
        long now = System.currentTimeMillis()/1000;
        managedKeys.addKey(ManagedKey.<KeyPair>builder()
                .setKey(pair)
                .setId(id)
                .setAlgorithm(algorithm)
                .setNotBefore(now)
                .setOup(60)
                .setRup(60*3)
                .build());

        return ManagedKey.<PublicKey>builder()
                .setKey(pair.getPublic())
                .setId(id)
                .setAlgorithm(algorithm)
                .setNotBefore(now)
                .setOup(60)
                .setRup(60*3)
                .build();
    }

    public ManagedKey<PublicKey> createKeyPair(String algorithm, int keySize, KeyOps... ops) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        for (KeyOps op : ops) {
            if (op == KeyOps.WRAP_KEY || op == KeyOps.UNWRAP_KEY || op == KeyOps.DERIVE_BITS || op == KeyOps.DERIVE_KEY) {
                throw new UnsupportedOperationException("Invalid operation for key type: " + op.toString());
            }
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm);
        g.initialize(keySize);
        KeyPair pair = g.generateKeyPair();
        String id = nextId();
        long now = System.currentTimeMillis()/1000;
        managedKeys.addKey(ManagedKey.<KeyPair>builder()
                .setKey(pair)
                .setId(id)
                .setAlgorithm(algorithm)
                .setNotBefore(now)
                .setOup(60)
                .setRup(60*3)
                .build());

        return ManagedKey.<PublicKey>builder()
                .setKey(pair.getPublic())
                .setId(id)
                .setAlgorithm(algorithm)
                .setNotBefore(now)
                .setOup(60)
                .setRup(60*3)
                .build();
    }

    public ManagedKey<PublicKey> getPublicKey(String keyId) {
        ManagedKey mk = managedKeys.getKey(keyId);
        KeyPair pair = (KeyPair)mk.getKey();
        return ManagedKey.<PublicKey>builder()
                .setKey(pair.getPublic())
                .setId(mk.getId())
                .setAlgorithm(mk.getAlgorithm())
                .setNotBefore(mk.getNotBefore())
                .setOup(mk.getOup())
                .setRup(mk.getRup())
                .build();
    }

    public String deriveKey(String algorithm, String parentId, KeyOps... ops) {
        throw new UnsupportedOperationException();
    }

    public static void main(String... args) throws Exception {
        KeyManager kms = new KeyManager();
        String aesId = kms.createKey("AES", 256, KeyOps.ENCRYPT, KeyOps.DECRYPT);
        ManagedKey<PublicKey> rsaPub = kms.createKeyPair("RSA", 2048, KeyOps.ENCRYPT, KeyOps.DECRYPT, KeyOps.SIGN, KeyOps.VERIFY);
        String rsaId = rsaPub.getId();
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256k1");
        ManagedKey<PublicKey> ecPub = kms.createKeyPair("EC", spec, KeyOps.SIGN, KeyOps.VERIFY);
        String ecdsaId = ecPub.getId();
        String hmacId = kms.createKey("HmacSHA512", 256, KeyOps.SIGN, KeyOps.VERIFY);

        byte[] data = "Hello KMS!".getBytes();
        GCMParameterSpec gcmParams = new GCMParameterSpec(128, new byte[256]);
        byte[] enc = kms.encrypt(data, aesId, "GCM/NoPadding", gcmParams);
        byte[] dec = kms.decrypt(enc, aesId, "GCM/NoPadding", gcmParams);
        System.out.println("AES Enc: " + Base64.encodeBase64String(enc));
        System.out.println("AES Dec: " + new String(dec));

        enc = kms.encrypt(data, rsaId, "ECB/OAEPWithSHA-256AndMGF1Padding");
        dec = kms.decrypt(enc, rsaId, "ECB/OAEPWithSHA-256AndMGF1Padding");
        System.out.println("RSA Enc: " + Base64.encodeBase64String(enc));
        System.out.println("RSA Dec: " + new String(dec));

        enc = kms.sign(data, ecdsaId, "SHA256");
        boolean verified = kms.verify(data, enc, ecdsaId, "SHA256");
        System.out.println("EC Sig: " + Base64.encodeBase64String(enc));
        System.out.println("Verified: " + verified);

        enc = kms.sign(data, hmacId, "SHA512");
        verified = kms.verify(data, enc, hmacId, "SHA512");
        System.out.println("HMAC Sig: " + Base64.encodeBase64String(enc));
        System.out.println("Verified: " + verified);


       /* for (Provider p : Security.getProviders("AlgorithmParameters.EC")) {
            System.out.println(p.getName());
            String cs = p.getService("AlgorithmParameters", "EC").getAttribute("SupportedCurves");
            String[] curves = cs.split("[|]");
            for (String c : curves) {
                System.out.println("\t" + c);
            }
        }*/
    }
}
