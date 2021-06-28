Format Preserving Encryption
============================

This library contains algorithms for format preserving encryption. FPE algorithms are designed
such that the ciphertext size and format matches the plaintext size and format.

The algorithms implemented are:
* NIST SP 800-38G - FF3
* NIST SP 800-38Gr1 - FF1 and FF3-1


### Usage
All implementations require a finite alphabet representing the valid symbols for the plaintext
and ciphertext. In order for implementations to be compatible they must use the same alphabet
and the alphabet symbols must be in the same order. Several predefined alphabets are avaliable
in the `RadixEncoders` class.

Additionally, all implementations support the use of a "tweak". The tweak does not need to be secret.
The output depends on both the key and the tweak parameters. Judicious use of tweaks can improve
the security of the system. The tweak and the alphabet are specified as parameters of the algormthm
using the `FFXAlgorithmParameterSpec`.

The FFX implementations are all modes of AES operation and thus take an AES key. They all
support key sizes of 128, 192, and 256 bits.

#### Sample Code
```java
    byte[] keyBytes = Hex.decode("2B7E151628AED2A6ABF7158809CF4F3C");
    SecretKey key = new SecretKeySpec(keyBytes, "AES");
    FF1 ff1 = new FF1();
    FFXAlgorithmParameterSpec spec = new FFXAlgorithmParameterSpec(RadixEncoders.BASE10);
    ff1.init(key, spec);

    String encrypted = ff1.encrypt("0123456789");
    System.out.println(encrypted); // outputs 2433477484

    String plaintext = ff1.decrypt("2433477484");
    System.out.println(plaintext); // outputs 0123456789
```

### References
* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
* https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF3samples.pdf