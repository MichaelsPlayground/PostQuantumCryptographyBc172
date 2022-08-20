package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.BCNTRULPRimePrivateKey;

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

public class PqcNtruLPRimeKemSo2 {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the newest Bouncy Castle beta file that includes the PQC provider
        // get Bouncy Castle here: https://downloads.bouncycastle.org/betas/
        // tested with BC version 1.72 Beta 13
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC NTRU LPRime kem");

        NTRULPRimeParameters ntruLPRimeParameter = NTRULPRimeParameters.ntrulpr653;

        System.out.println("generate the NTRULPRime keypair");
        AsymmetricCipherKeyPair keyPair;
        NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
        keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(new SecureRandom(), ntruLPRimeParameter));
        keyPair = keyPairGenerator.generateKeyPair();

        // storing the key as byte array
        System.out.println("storing the keys as byte array");
        byte[] privateKeyByte = ((NTRULPRimePrivateKeyParameters) keyPair.getPrivate()).getEncoded();
        byte[] publicKeyByte = ((NTRULPRimePublicKeyParameters) keyPair.getPublic()).getEncoded();

        System.out.println("privateKeyByte.length: " + privateKeyByte.length);
        System.out.println("publicKeyByte.length:  " + publicKeyByte.length);

        AsymmetricKeyParameter asymmetricKeyParameter = keyPair.getPrivate();
        System.out.println("asymmetricKeyParameter: " + asymmetricKeyParameter.toString());
        // storing the key as byte array
        NTRULPRimeKeyParameters ntruLPlRimeKeyParameters = new NTRULPRimeKeyParameters(true, ntruLPRimeParameter);



        /*
        try {
            String a = "";
            AsymmetricKeyParameter privateKeyRebuild = PrivateKeyFactory.createKey(a);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
            PrivateKey privateKey1 = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            privateKeyLoad = (AsymmetricKeyParameter) privateKey1;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
*/


        // https://github.com/bcgit/bc-java/tree/master/prov/src/main/java/org/bouncycastle/pqc/jcajce/provider/ntruprime
        AsymmetricKeyParameter privateKeyAKP = keyPair.getPrivate();
        /*
        BCNTRULPRimePrivateKey bcntrulpRimePrivateKey;//
        //bcntrulpRimePrivateKey = (BCNTRULPRimePrivateKey) privateKeyAKP;
        PrivateKeyInfo privateKeyInfo = null;
        String a = "";
        privateKeyInfo = new PrivateKeyInfo(a);
        try {
            bcntrulpRimePrivateKey = new BCNTRULPRimePrivateKey(privateKeyInfo);
        } catch (IOException e) {
            e.printStackTrace();
        }




        //byte[] privateKeyByte = ((NTRULPRimePrivateKeyParameters) privateKey).getEncoded();
        privateKeyByte = new byte[0];

        PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
        bcntrulpRimePrivateKey = (BCNTRULPRimePrivateKey) privateKey;

        // = new BCNTRULPRimePrivateKey(PrivateKeyInfo.getInstance(ntruLPlRimeKeyParameters));
        privateKeyByte = bcntrulpRimePrivateKey.getEncoded();
        System.out.println("*** privateKeyByteLength: " + privateKeyByte.length);

*/
        System.out.println("get the private key from encoded");
        AsymmetricKeyParameter privateKeyLoad = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("NTRULPRIME", "BCPQC");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
            PrivateKey privateKey1 = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            privateKeyLoad = (AsymmetricKeyParameter) privateKey1;
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
