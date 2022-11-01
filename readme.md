# Post Quantum Cryptography with Bouncy Castle

This version uses the final version of Bouncy Castle (1.72) to use most of the PQC finalists and other candidates.

In your build.gradle file (project) add this line in dependencies section and yes, it is the extended provider  
to run the NTRU examples:

```plaintext
implementation group: 'org.bouncycastle', name: 'bcprov-ext-jdk18on', version: '1.72'
```

Your AndroidManifest.xml needs to appendings for write a file to external storage and send an email:
```plaintext
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>

    ...
    </application>
    <queries>
        <intent>
            <action android:name="android.intent.action.SENDTO" />
            <data android:scheme="*" />
        </intent>
    </queries>
```

These implementations for Post-Quantum Algorithms are available:

The selected algorithms:
```plaintext
Selected Algorithms: Public-key Encryption and Key-establishment Algorithms:
CRYSTALS-KYBER (3 parameter sets)

Selected Algorithms: Digital Signature Algorithms:
CRYSTALS-DILITHIUM (3 parameter sets)
FALCON (2 parameter sets)
SPHINCS+ (24 parameter sets)
```

Round 4 alternative algorithms/submissions:
```plaintext
Round 4 Submissions: Public-key Encryption and Key-establishment Algorithms
BIKE (3 parameter sets)
Classic McEliece (6 parameter sets)
HQC (3 parameter sets)
SIKE (not available here because this algorithm is broken)
```

Some candidates from earlier rounds:
```plaintext
Public-key Encryption and Key-establishment Algorithms
NTRU (7 parameter sets)
FRODO (6 parameter sets)
SABER (9 parameter sets)
NTRULPrime (6 parameter sets)
SNTRUPrime (6 parameter sets)

Digital Signature Algorithms
Rainbow (n.a., at the moment this algorithm got updated in Bouncy Castle 1.72)
Picnic (12 parameter sets)
```

Further information on Post-Quantum Algorithms and the NIST competition:

The official NIST homepage: https://csrc.nist.gov/Projects/post-quantum-cryptography

Selected algorithms: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

Round 4 submissions: https://csrc.nist.gov/Projects/post-quantum-cryptography/round-4-submissions

Bouncy Castle release notes: https://github.com/bcgit/bc-java/blob/master/docs/releasenotes.html

**Be aware that this is a concept study to run all PQC algorithms. As some algorithms do have some more 
parametersets they may take a long time to finish. Keep in my mind the warning when starting the app:**

**Some algorithms will run several minutes to proceed and can block your complete user interface, so 
please run the app only when you don\'t need your smartphone for the next minutes.**

Each algorithm is running the same flow:
```plaintext
- generate an asymmetric key pair with a parameterset
- encode the keys to a byte array (e.g. for storing anywhere)
- rebuild the keys from the encoded form

for kems:
- exchange the public keys between the two parties
- generate the encryption key on sender side with privateKeySender and publicKeyRecipient
- generate the decryption key on recipients side with privateKeyRecipient and publicKeySender
- compare both keys (should be equal) 

for signatures:
- sign a plaintext with the privateKey
- verify the signature with the publicKey
```

![app_view_after_starting](docs/app03.png?raw=true)

Here are 2 sample logfiles for the [Chrystals-Kyber KEM](sample_chrystal_kyber.md) and the 
[Chrystals-Dilithium SIG](sample_chrystal_dilithium.md) algorithms.
