# Post Quantum Cryptography wwith Bouncy Castle

This version uses a Beta version of Bouncy Castle (1.72 Beta 15) to use most of the PQC finalists and candidates.

see the Bouncy Castle release notes: https://github.com/bcgit/bc-java/blob/master/docs/releasenotes.html

https://downloads.bouncycastle.org/betas/bcprov-ext-jdk18on-172b15.jar 

Official NIST homepage: https://csrc.nist.gov/Projects/post-quantum-cryptography

Selected algorithms: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

**Be aware that this is a concept study to run all PQC algorithms. There is no output to the Android  
application but only on the console, so you need to run the code in Android Studio and open the "Run" tab. 
The complete run with all algorithms and parameter sets will take some minutes to complete, so please be 
patient.**

Each algorithm is running the same flow:
```plaintext
- generate an asymmetric key pair with a parameterset
- encode the key to a byte array (e.g. for storing anywhere)
- rebuild the key from its encoded form

for kems:
- exchange the public keys between the two parties
- generate the encryption key on sender side with privateKeySender and publicKeyRecipient
- generate the decryption key on recipients side with privateKeyRecipient and publicKeySender
- compare both keys

for signatures:
- sign a plaintext with the privateKey
- verify the signature with the publicKey
```

```plaintext
Selected Algorithms: Public-key Encryption and Key-establishment Algorithms:
CRYSTALS-KYBER
```

```plaintext
Selected Algorithms: Digital Signature Algorithms:
CRYSTALS-DILITHIUM (As BC in 1.72 Beta 10 does not provide an implementation of Chrystals-Dilithium  
this signature scheme uses an other implementation: https://github.com/mthiim/dilithium-java)
FALCON
SPHINCS+
```

Round 4 searching for alternatives: https://csrc.nist.gov/Projects/post-quantum-cryptography/round-4-submissions

```plaintext
Round 4 Submissions: Public-key Encryption and Key-establishment Algorithms
BIKE
Classic McEliece
HQC (not available here)
SIKE (not available here) - Note: this algorithm seems to get broken
```

Round 3 candidates: 
```plaintext
Public-key Encryption and Key-establishment Algorithms
Classic McEliece (merger of Classic McEliece and NTS-KEM): https://classic.mceliece.org/
CRYSTALS-KYBER: https://pq-crystals.org/
NTRU: https://ntru.org/
NTRULPrime
SNTRUPrime
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

Bouncy Castle Release notes: https://www.bouncycastle.org/latest_releases.html

Bouncy Castle Provider for PQC: https://github.com/bcgit/bc-java/tree/master/prov/src/main/java/org/bouncycastle/pqc/jcajce/provider

Bouncy Castle Specs for PQC: https://github.com/bcgit/bc-java/tree/master/prov/src/main/java/org/bouncycastle/pqc/jcajce/spec

Bouncy Castle Tests for PQC: https://github.com/bcgit/bc-java/tree/master/prov/src/test/java/org/bouncycastle/pqc/jcajce/provider/test
