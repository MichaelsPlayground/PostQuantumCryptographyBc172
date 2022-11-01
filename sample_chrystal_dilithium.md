# Sample logfile for Chrystals-Dilithium SIG

```plaintext
PQC Chrystals Dilithium signature (BC implementation)

************************************
* # # SERIOUS SECURITY WARNING # # *
* This program is a CONCEPT STUDY  *
* for the algorithm                *
* Chrystals Dilithium [signature]  *
* The program is using an          *
* parameter set that I cannot      *
* check for the correctness of the *
* output and other details         *
*                                  *
*    DO NOT USE THE PROGRAM IN     *
*    ANY PRODUCTION ENVIRONMENT    *
************************************

****************************************

Chrystals Dilithium signature with parameterset dilithium2

generated private key length: 3912
generated public key length:  1346

* * * sign the dataToSign with the private key * * *
signature length: 2420 data: ac0a3d694ad6ff7a620f273fde348feb ...

* * * verify the signature with the public key * * *
the signature is verified: true

****************************************

Chrystals Dilithium signature with parameterset dilithium3

generated private key length: 6024
generated public key length:  1986

* * * sign the dataToSign with the private key * * *
signature length: 3293 data: 30549f3a33992eea938024c41d50f0d1 ...

* * * verify the signature with the public key * * *
the signature is verified: true

****************************************

Chrystals Dilithium signature with parameterset dilithium5

generated private key length: 7528
generated public key length:  2626

* * * sign the dataToSign with the private key * * *
signature length: 4595 data: 0b10ac044bc6c98fad6f9e5efcf71a81 ...

* * * verify the signature with the public key * * *
the signature is verified: true

****************************************

Test results
parameter spec name  priKL   pubKL    sigL  sigV
dilithium2            3912    1346    2420  true
dilithium3            6024    1986    3293  true
dilithium5            7528    2626    4595  true

Legend: priKL privateKey length, pubKL publicKey length, sigL signature length, sigV signature verified

****************************************
```