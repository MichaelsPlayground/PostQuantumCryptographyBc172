# Sample logfile for Chrystals-Kyber KEM

```plaintext
PQC Chrystals-Kyber KEM

************************************
* # # SERIOUS SECURITY WARNING # # *
* This program is a CONCEPT STUDY  *
* for the algorithm                *
* Chrystals-Kyber [key exchange    *
* mechanism]                       *
* The program is using an          *
* parameter set that I cannot      *
* check for the correctness of the *
* output and other details         *
*                                  *
*    DO NOT USE THE PROGRAM IN     *
*    ANY PRODUCTION ENVIRONMENT    *
************************************

****************************************

Chrystals-Kyber KEM with parameterset kyber512

generated private key length: 1688
generated public key length:  834

Encryption side: generate the encryption key and the encapsulated key
encryption key length: 16 key: 618df6a4c429da50ab6c72d6d4847c52
encapsulated key length: 768 key: 45c1df5c9fcad76db3871656e4f3102e ...

Decryption side: receive the encapsulated key and generate the decryption key
decryption key length: 16 key: 618df6a4c429da50ab6c72d6d4847c52
decryption key is equal to encryption key: true

****************************************

Chrystals-Kyber KEM with parameterset kyber768

generated private key length: 2456
generated public key length:  1218

Encryption side: generate the encryption key and the encapsulated key
encryption key length: 24 key: 5c676b2f35ed452779438f96f0b2cab92546ab45307b101f
encapsulated key length: 1088 key: 19d336551bcfaea404dd67235c629f62 ...

Decryption side: receive the encapsulated key and generate the decryption key
decryption key length: 24 key: 5c676b2f35ed452779438f96f0b2cab92546ab45307b101f
decryption key is equal to encryption key: true

****************************************

Chrystals-Kyber KEM with parameterset kyber1024

generated private key length: 3224
generated public key length:  1602

Encryption side: generate the encryption key and the encapsulated key
encryption key length: 32 key: f1651c857bbbb01d0a1a32cdeb628f19d54a5dc787408d97354871b62e06fcd3
encapsulated key length: 1568 key: e7c638664c7b9146e1eff3c1b11a16d8 ...

Decryption side: receive the encapsulated key and generate the decryption key
decryption key length: 32 key: f1651c857bbbb01d0a1a32cdeb628f19d54a5dc787408d97354871b62e06fcd3
decryption key is equal to encryption key: true

****************************************

Test results
parameter spec name  priKL   pubKL encKL capKL  keyE
kyber512              1688     834    16   768  true
kyber768              2456    1218    24  1088  true
kyber1024             3224    1602    32  1568  true

Legend: priKL privateKey length, pubKL publicKey length, encKL encryption key length, capKL encapsulated key length
****************************************
```