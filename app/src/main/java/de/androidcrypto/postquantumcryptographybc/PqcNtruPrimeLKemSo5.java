package de.androidcrypto.postquantumcryptographybc;


import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
//import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
//import org.bouncycastle.pqc.jcajce.provider.ntruprime.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.ntruprime2.BCNTRULPRimePrivateKey;
import org.bouncycastle.pqc.jcajce.provider.ntruprime2.BCNTRULPRimePublicKey;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PqcNtruPrimeLKemSo5 {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the newest Bouncy Castle beta file that includes the PQC provider
        // get Bouncy Castle here: https://downloads.bouncycastle.org/betas/
        // tested with BC version 1.72 Beta 13
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC NTRU LPRime kem");

        NTRULPRimeParameters ntrulpRimeParameter = NTRULPRimeParameters.ntrulpr653;

        System.out.println("generate the NTRULPRime keypair");
        AsymmetricCipherKeyPair keyPair;
        NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
        keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(new SecureRandom(), ntrulpRimeParameter));
        keyPair = keyPairGenerator.generateKeyPair();

        AsymmetricKeyParameter privateKeyOriginal = keyPair.getPrivate();
        AsymmetricKeyParameter publicKeyOriginal = keyPair.getPublic();

        System.out.println("### using BCNTRULPRimePrivateKey ###");
        PrivateKeyInfo privateKeyInfoOriginal = null;
        SubjectPublicKeyInfo subjectPublicKeyInfoOriginal = null;
        BCNTRULPRimePrivateKey privateKeyLoadN;
        BCNTRULPRimePublicKey publicKeyLoadN;

        try {
            System.out.println("generate a BCNTRULPRimePrivateKey");
            // https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/pqc/jcajce/provider/ntruprime/BCNTRULPRimePrivateKey.java
            privateKeyInfoOriginal = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyOriginal);
            BCNTRULPRimePrivateKey bcntrulpRimePrivateKeyOriginal = new BCNTRULPRimePrivateKey(privateKeyInfoOriginal);
            subjectPublicKeyInfoOriginal = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyOriginal);
            BCNTRULPRimePublicKey bcntrulpRimePublicKeyOriginal = new BCNTRULPRimePublicKey(subjectPublicKeyInfoOriginal);
            if (bcntrulpRimePrivateKeyOriginal == null) {
                System.out.println("bcntrulpRimePrivateKeyOriginal == null");
                return;
            }
            byte[] bcntrulpRimePrivateKeyOriginalByte = bcntrulpRimePrivateKeyOriginal.getEncoded();
            System.out.println("bcntrulpRimePrivateKeyOriginalByte: " + bytesToHex(bcntrulpRimePrivateKeyOriginalByte));
            KeyFactory keyFactory = KeyFactory.getInstance("NTRULPRIME", "BCPQC");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bcntrulpRimePrivateKeyOriginalByte);
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            privateKeyLoadN = (org.bouncycastle.pqc.jcajce.provider.ntruprime2.BCNTRULPRimePrivateKey) privateKey;

            System.out.println("privateKeyLoad: " + privateKeyLoadN.getEncoded().length +
                    " " + privateKeyLoadN);
            System.out.println("generate a BCNTRULPRimePublicKey");
            // https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/pqc/jcajce/provider/ntruprime/BCNTRULPRimePublicKey.java
            if (bcntrulpRimePublicKeyOriginal == null) {
                System.out.println("bcntrulpRimePublicKeyOriginal == null");
                return;
            }
            byte[] bcntrulpRimePublicKeyOriginalByte = bcntrulpRimePublicKeyOriginal.getEncoded();
            System.out.println("bcntrulpRimePublicKeyOriginalByte: " + bytesToHex(bcntrulpRimePublicKeyOriginalByte));
            //KeyFactory keyFactory = KeyFactory.getInstance("NTRULPRIME", "BCPQC");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bcntrulpRimePublicKeyOriginalByte);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            publicKeyLoadN = (org.bouncycastle.pqc.jcajce.provider.ntruprime2.BCNTRULPRimePublicKey) publicKey;
            System.out.println("publicKeyLoadN: " + publicKeyLoadN.getEncoded().length +
                    " "  + publicKeyLoadN);

            SecretWithEncapsulation secretKeyWithEncapsulation = pqcNtruLPRimeGenerateSecretWithEncapsulation(publicKeyOriginal);
            // this is the encryption key for e.g. aes encryption
            byte[] encryptionKey = secretKeyWithEncapsulation.getSecret();
            System.out.println("encryption key length: " + encryptionKey.length + " key: " + bytesToHex(encryptionKey));
            // this is the encapsulated key that is send to the receiver
            byte[] encapsulatedKey = secretKeyWithEncapsulation.getEncapsulation();
            byte[] decryptedKey = pqcNtruLRimeExtractSecretWithEncapsulationR(privateKeyLoadN, encapsulatedKey);
            System.out.println("decryption key length: " + decryptedKey.length + " key: " + bytesToHex(decryptedKey));

            System.out.println("now trying to encapsulate a key with the rebuild private key");
            SecretWithEncapsulation secretKeyWithEncapsulationR = pqcNtruLPRimeGenerateSecretWithEncapsulationR(publicKeyLoadN);


        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        //System.exit(0);
/*
        // storing the key as byte array
        System.out.println("storing the keys as byte array");
        byte[] privateKeyByte = ((NTRULPRimePrivateKeyParameters) keyPair.getPrivate()).getEncoded();
        byte[] publicKeyByte = ((NTRULPRimePublicKeyParameters) keyPair.getPublic()).getEncoded();

        System.out.println("get the private key from encoded");
        AsymmetricKeyParameter privateKeyLoad = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("NTRULPRIME", "BCPQC");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            privateKeyLoad = (AsymmetricKeyParameter) privateKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        System.out.println("get the public key from encoded");
        AsymmetricKeyParameter publicKeyLoad = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("NTRULPRIME", "BCPQC");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyByte);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            publicKeyLoad = (AsymmetricKeyParameter) publicKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        if (privateKeyLoad != null) {
            System.out.println("privateKeyLoad: " + privateKeyLoad.toString());
        }
        if (publicKeyLoad != null) {
            System.out.println("publicKeyLoad: " + publicKeyLoad.toString());
        }


        System.out.println("*** TRYING TO use PrivateKeyInfo ***");
        AsymmetricKeyParameter privateKey1 = keyPair.getPrivate();
        try {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey1);
            System.out.println("privateKeyInfo: " + privateKeyInfo);
            // https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/pqc/jcajce/provider/ntruprime/BCNTRULPRimePrivateKey.java
            BCNTRULPRimePrivateKey bcntrulpRimePrivateKey = new BCNTRULPRimePrivateKey(privateKeyInfo);
            System.out.println("bcntrulpRimePrivateKey " + bcntrulpRimePrivateKey);
            byte[] bcntrulpRimePrivateKeyByte = bcntrulpRimePrivateKey.getEncoded();
            System.out.println("bcntrulpRimePrivateKeyByte.length: " + bcntrulpRimePrivateKeyByte.length);

            System.out.println("get the private key from encoded");
            BCNTRULPRimePrivateKey privateKey1Load = null;
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("NTRULPRIME", "BCPQC");
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bcntrulpRimePrivateKeyByte);
                PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
                //privateKey1Load = (BCNTRULPRimePrivateKey) privateKey;
                privateKey1Load = (BCNTRULPRimePrivateKey) privateKey;
                System.out.println("*** privateKey1Load: " + privateKey1Load.toString());
                System.out.println("now trying to encapsulate a key with the original key");
                SecretWithEncapsulation secretKeyWithEncapsulation = pqcNtruLPRimeGenerateSecretWithEncapsulation(publicKeyOriginal);
                // this is the encryption key for e.g. aes encryption
                byte[] encryptionKey = secretKeyWithEncapsulation.getSecret();
                System.out.println("encryption key length: " + encryptionKey.length + " key: " + bytesToHex(encryptionKey));
                // this is the encapsulated key that is send to the receiver
                byte[] encapsulatedKey = secretKeyWithEncapsulation.getEncapsulation();
                byte[] decryptedKey = pqcNtruLRimeExtractSecretWithEncapsulation(privateKeyOriginal, encapsulatedKey);
                System.out.println("decryption key length: " + decryptedKey.length + " key: " + bytesToHex(decryptedKey));

                System.out.println("now trying to encapsulate a key with the rebuild private key");
                SecretWithEncapsulation secretKeyWithEncapsulationR = pqcNtruLPRimeGenerateSecretWithEncapsulation(publicKeyOriginal);
                // this is the encryption key for e.g. aes encryption
                byte[] encryptionKeyR = secretKeyWithEncapsulationR.getSecret();
                System.out.println("encryption key length: " + encryptionKeyR.length + " key: " + bytesToHex(encryptionKeyR));
                // this is the encapsulated key that is send to the receiver
                byte[] encapsulatedKeyR = secretKeyWithEncapsulationR.getEncapsulation();

                // todo work on this
                byte[] decryptedKeyR = pqcNtruLRimeExtractSecretWithEncapsulationR(privateKey1Load, encapsulatedKey);
                System.out.println("decryption key length: " + decryptedKeyR.length + " key: " + bytesToHex(decryptedKeyR));


            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
                e.printStackTrace();
            }


        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("*** TRYING TO use PrivateKeyInfo END ***");

 */
    }

/*
    private static AsymmetricKeyParameter getNtruLPRimePrivateKeyFromEncoded(byte[] enca, byte[] pk, byte[] rho, byte[] hash, NTRULPRimeParameters ntruLPrimeParameter) {
        return new NTRULPRimePrivateKeyParameters(ntruLPrimeParameter, enca, pk, rho, hash);
    }
*/
    private static SecretWithEncapsulation pqcNtruLPRimeGenerateSecretWithEncapsulation(AsymmetricKeyParameter publicKey) {
        NTRULPRimeKEMGenerator kemGenerator = new NTRULPRimeKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(publicKey);
        return secretEncapsulation;
    }

    private static SecretWithEncapsulation pqcNtruLPRimeGenerateSecretWithEncapsulationR(org.bouncycastle.pqc.jcajce.provider.ntruprime2.BCNTRULPRimePublicKey publicKey) {
        NTRULPRimeKEMGenerator kemGenerator = new NTRULPRimeKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(publicKey.getKeyParams());
        return secretEncapsulation;
    }

    /*
    private static byte[] pqcNtruLRimeExtractSecretWithEncapsulation(AsymmetricKeyParameter privateKey, byte[] secretToDecrypt) {
        NTRULPRimeKEMExtractor kemExtractor = new NTRULPRimeKEMExtractor((NTRULPRimePrivateKeyParameters) privateKey);
        return kemExtractor.extractSecret(secretToDecrypt);
    }
*/

    private static byte[] pqcNtruLRimeExtractSecretWithEncapsulationR(org.bouncycastle.pqc.jcajce.provider.ntruprime2.BCNTRULPRimePrivateKey privateKey, byte[] secretToDecrypt) {
        NTRULPRimeKEMExtractor kemExtractor = new NTRULPRimeKEMExtractor(privateKey.getKeyParams());
        return kemExtractor.extractSecret(secretToDecrypt);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}

/*
java.security.spec.InvalidKeySpecException: java.io.IOException: long form definite-length more than 31 bits
	at org.bouncycastle.pqc.jcajce.provider.ntruprime.NTRULPRimeKeyFactorySpi.engineGeneratePrivate(NTRULPRimeKeyFactorySpi.java:37)
	at java.base/java.security.KeyFactory.generatePrivate(KeyFactory.java:384)
	at de.androidcrypto.postquantumcryptographybc.PqcNtruPrimeLKemSo.main(PqcNtruPrimeLKemSo.java:54)
java.security.spec.InvalidKeySpecException: java.lang.IllegalArgumentException: failed to construct sequence from byte[]: Extra data detected in stream
	at org.bouncycastle.pqc.jcajce.provider.ntruprime.NTRULPRimeKeyFactorySpi.engineGeneratePublic(NTRULPRimeKeyFactorySpi.java:60)
	at java.base/java.security.KeyFactory.generatePublic(KeyFactory.java:346)
	at de.androidcrypto.postquantumcryptographybc.PqcNtruPrimeLKemSo.main(PqcNtruPrimeLKemSo.java:65)

 */

/*
so issue:
https://github.com/bcgit/bc-java/issues/1208

NTRULPRime private and public key rebuilding from encoded form fails (PQC)

Hi team,
I'm working with the Post Quantum Crypto algorithm "NTRULPrime" to securely generate a shared secret ("KEM").

The complete process is working (generation of the keypair, generate the encapsulatedKey with the public key and
extract the secret key with the private key).

However, when trying to rebuild the keys from its encoded using the KeyFactory form I'm getting errors:

java.security.spec.InvalidKeySpecException: java.io.IOException: long form definite-length more than 31 bits
	at org.bouncycastle.pqc.jcajce.provider.ntruprime.NTRULPRimeKeyFactorySpi.engineGeneratePrivate(NTRULPRimeKeyFactorySpi.java:37)
	at java.base/java.security.KeyFactory.generatePrivate(KeyFactory.java:384)
	at de.androidcrypto.postquantumcryptographybc.PqcNtruPrimeLKemSo.main(PqcNtruPrimeLKemSo.java:54)
java.security.spec.InvalidKeySpecException: java.lang.IllegalArgumentException: failed to construct sequence from byte[]: Extra data detected in stream
	at org.bouncycastle.pqc.jcajce.provider.ntruprime.NTRULPRimeKeyFactorySpi.engineGeneratePublic(NTRULPRimeKeyFactorySpi.java:60)
	at java.base/java.security.KeyFactory.generatePublic(KeyFactory.java:346)
	at de.androidcrypto.postquantumcryptographybc.PqcNtruPrimeLKemSo.main(PqcNtruPrimeLKemSo.java:65)

This happens as well when using the SNTRUPrime algorithm.

Here is the complete code, I'm using BouncyCastle Version 1.72 Beta 13:

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PqcNtruPrimeLKemSo {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the newest Bouncy Castle beta file that includes the PQC provider
        // get Bouncy Castle here: https://downloads.bouncycastle.org/betas/
        // tested with BC version 1.72 Beta 13
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC NTRU LPRime kem");

        NTRULPRimeParameters ntrulpRimeParameter = NTRULPRimeParameters.ntrulpr653;

        System.out.println("generate the NTRULPRime keypair");
        AsymmetricCipherKeyPair keyPair;
        NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
        keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(new SecureRandom(), ntrulpRimeParameter));
        keyPair = keyPairGenerator.generateKeyPair();

        // storing the key as byte array
        System.out.println("storing the keys as byte array");
        byte[] privateKeyByte = ((NTRULPRimePrivateKeyParameters) keyPair.getPrivate()).getEncoded();
        byte[] publicKeyByte = ((NTRULPRimePublicKeyParameters) keyPair.getPublic()).getEncoded();

        System.out.println("get the private key from encoded");
        AsymmetricKeyParameter privateKeyLoad = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("NTRULPRIME", "BCPQC");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            privateKeyLoad = (AsymmetricKeyParameter) privateKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        System.out.println("get the public key from encoded");
        AsymmetricKeyParameter publicKeyLoad = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("NTRULPRIME", "BCPQC");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyByte);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            publicKeyLoad = (AsymmetricKeyParameter) publicKey;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        if (privateKeyLoad != null) {
            System.out.println("privateKeyLoad: " + privateKeyLoad.toString());
        }
        if (publicKeyLoad != null) {
            System.out.println("publicKeyLoad: " + publicKeyLoad.toString());
        }
    }
}

Btw: The key rebuilding using

NTRULPRimePrivateKeyParameters(ntruPrimeParameter, f, ginv, pk, rho, hash)

is working but this is not using the encoded form but a bunch of data.

 */