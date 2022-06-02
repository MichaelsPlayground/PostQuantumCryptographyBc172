# Post Quantum Cryptography wwith Bouncy Castle

This version uses a Beta version of Bouncy Castle (1.72 Beta 02) to use the PQC Picnic Signature algorithm

https://downloads.bouncycastle.org/betas/bcprov-ext-jdk18on-172b02.jar 

Official NIST homepage: https://csrc.nist.gov/Projects/post-quantum-cryptography

Round 3 candidates: 
```plaintext
Public-key Encryption and Key-establishment Algorithms
Classic McEliece (merger of Classic McEliece and NTS-KEM): https://classic.mceliece.org/
CRYSTALS-KYBER: https://pq-crystals.org/
NTRU: https://ntru.org/
SABER: https://www.esat.kuleuven.be/cosic/pqcrypto/saber/

Alternate Candidates: Public-key Encryption and Key-establishment Algorithms
BIKE: http://bikesuite.org/
FrodoKEM: http://frodokem.org/
HQC: http://pqc-hqc.org/
NTRU Prime: https://ntruprime.cr.yp.to/
SIKE: http://sike.org/

Digital Signature Algorithms
CRYSTALS-DILITHIUM: https://pq-crystals.org/
FALCON: https://falcon-sign.info/
Rainbow: https://www.pqcrainbow.org/

Alternate Candidates: Digital Signature Algorithms
GeMSS: https://www-polsys.lip6.fr/Links/NIST/GeMSS.html
Picnic: https://microsoft.github.io/Picnic/
SPHINCS+: https://sphincs.org/
```


```plaintext
// https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on
implementation group: 'org.bouncycastle', name: 'bcprov-jdk18on', version: '1.71'
// https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk18on
implementation group: 'org.bouncycastle', name: 'bcpkix-jdk18on', version: '1.71'
```
Bouncy Castle Release notes: https://www.bouncycastle.org/latest_releases.html

Bouncy Castle Provider for PQC: https://github.com/bcgit/bc-java/tree/master/prov/src/main/java/org/bouncycastle/pqc/jcajce/provider

Bouncy Castle Specs for PQC: https://github.com/bcgit/bc-java/tree/master/prov/src/main/java/org/bouncycastle/pqc/jcajce/spec

Bouncy Castle Tests for PQC: https://github.com/bcgit/bc-java/tree/master/prov/src/test/java/org/bouncycastle/pqc/jcajce/provider/test

https://www.primekey.com/resources/three-key-takeaways-from-the-real-world-crypto-symposium-2022/:
```plaintext
The NIST PQC competition continues
Late last year, it was announced that the final algorithm set from the NIST PQC competition would be 
chosen in late March of this year. As one speaker so eloquently put it, we are now in late March, for 
very large values of late. NIST have not made any further announcements and the submission teams do 
not appear to have more information either. A possible reason for the pause is that there have been 
further advances in analysis of the candidates. An attack on Rainbow has meant that all its parameter 
sets have been effectively downgraded one level in security, more recently an improved dual lattice 
attack has been published which also downgrades the security of algorithms like SABER, Crystals-Dilithium, 
and Crystals-Kyber. This does not mean that any of these algorithms are inherently broken, but it may 
mean that parameter sizes need to be revised and this has knock-on effects as to the utility of the 
algorithms which probably in turn affects an algorithm's suitability for selection. So maybe – just 
maybe – NIST are having a bit more of a think. One thing seems clear: the "shape", as it were, of the 
algorithms we will migrate to in the future does not look like it's going to change. More on this one 
a bit later!
```

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


