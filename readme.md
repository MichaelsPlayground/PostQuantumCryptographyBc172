# Post Quantum Cryptography wwith Bouncy Castle




// https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on
implementation group: 'org.bouncycastle', name: 'bcprov-jdk18on', version: '1.71'
// https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk18on
implementation group: 'org.bouncycastle', name: 'bcpkix-jdk18on', version: '1.71'


https://classic.mceliece.org/nist/mceliece-20201010.pdf
KEM: Classic McElice

```plaintext
Sizes of inputs and outputs to the complete cryptographic functions. All sizes are expressed in bytes.
                PubKey  PriKey CiphText SessKey
mceliece348864   261120  6492    128      32
mceliece460896   524160 13608    188      32
mceliece6688128 1044992 13932    240      32
mceliece6960119 1047319 13948    226      32
mceliece8192128 1357824 14120    240      32

7 Expected strength (2.B.4) for each parameter set
7.1 Parameter set kem/mceliece348864 IND-CCA2 KEM, Category 1.
7.2 Parameter set kem/mceliece348864f IND-CCA2 KEM, Category 1.
7.3 Parameter set kem/mceliece460896 IND-CCA2 KEM, Category 3.
7.4 Parameter set kem/mceliece460896f IND-CCA2 KEM, Category 3.
7.5 Parameter set kem/mceliece6688128 IND-CCA2 KEM, Category 5.
7.6 Parameter set kem/mceliece6688128f IND-CCA2 KEM, Category 5.
7.7 Parameter set kem/mceliece6960119 IND-CCA2 KEM, Category 5.
7.8 Parameter set kem/mceliece6960119f IND-CCA2 KEM, Category 5.
7.9 Parameter set kem/mceliece8192128 IND-CCA2 KEM, Category 5.
7.10 Parameter set kem/mceliece8192128f IND-CCA2 KEM, Category 5.
```


