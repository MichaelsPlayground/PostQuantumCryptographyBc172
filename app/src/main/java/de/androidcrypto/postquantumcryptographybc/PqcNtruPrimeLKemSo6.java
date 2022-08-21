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
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.BCNTRULPRimePrivateKey;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.BCNTRULPRimePublicKey;

import java.io.IOException;
import java.lang.reflect.Field;
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

public class PqcNtruPrimeLKemSo6 {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the newest Bouncy Castle beta file that includes the PQC provider
        // get Bouncy Castle here: https://downloads.bouncycastle.org/betas/
        // tested with BC version 1.72 Beta 13
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC NTRU LPRime kem SO 6");

        NTRULPRimeParameters ntruLPRimeParameter = NTRULPRimeParameters.ntrulpr653;

        System.out.println("generate the NTRULPRime keypair");
        AsymmetricCipherKeyPair keyPair;
        NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
        keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(new SecureRandom(), ntruLPRimeParameter));
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
            privateKeyLoadN = (BCNTRULPRimePrivateKey) privateKey;

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
            publicKeyLoadN = (BCNTRULPRimePublicKey) publicKey;
            System.out.println("publicKeyLoadN: " + publicKeyLoadN.getEncoded().length +
                    " " + publicKeyLoadN);

            SecretWithEncapsulation secretKeyWithEncapsulation = pqcNtruLPRimeGenerateSecretWithEncapsulationR(publicKeyLoadN);
            // this is the encryption key for e.g. aes encryption
            byte[] encryptionKey = secretKeyWithEncapsulation.getSecret();
            System.out.println("encryption key length: " + encryptionKey.length + " key: " + bytesToHex(encryptionKey));
            // this is the encapsulated key that is send to the receiver
            byte[] encapsulatedKey = secretKeyWithEncapsulation.getEncapsulation();
            byte[] decryptedKey = pqcNtruLRimeExtractSecretWithEncapsulationR(privateKeyLoadN, encapsulatedKey);
            System.out.println("decryption key length: " + decryptedKey.length + " key: " + bytesToHex(decryptedKey));
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    private static SecretWithEncapsulation pqcNtruLPRimeGenerateSecretWithEncapsulation(AsymmetricKeyParameter publicKey) {
        NTRULPRimeKEMGenerator kemGenerator = new NTRULPRimeKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(publicKey);
        return secretEncapsulation;
    }

    private static SecretWithEncapsulation pqcNtruLPRimeGenerateSecretWithEncapsulationR(BCNTRULPRimePublicKey publicKey) {
        NTRULPRimePublicKeyParameters ntrulpRimePublicKeyParameters = null;
        try {
            // change the access from none/private to public
            Field[] formFields = publicKey.getClass().getDeclaredFields();
            if (formFields != null) {
                for (Field formField : formFields) {
                    // Necessary to be able to read a private field
                    formField.setAccessible(true);
                    Class type = formField.getType();
                    // how do I get the current value in this current object?
                    // Get the value of the field in the form object
                    Object fieldValue = formField.get(publicKey);
                    if (fieldValue instanceof org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters) {
                        ntrulpRimePublicKeyParameters = (org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters) fieldValue;
                    }
                }
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        NTRULPRimeKEMGenerator kemGenerator = new NTRULPRimeKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(ntrulpRimePublicKeyParameters);
        return secretEncapsulation;
    }

    private static byte[] pqcNtruLRimeExtractSecretWithEncapsulationR(BCNTRULPRimePrivateKey privateKey, byte[] secretToDecrypt) {
        System.out.println("using REFLECTION in pqcNtruLRimeExtractSecretWithEncapsulationR for getKeyParams()");
        NTRULPRimePrivateKeyParameters ntrulpRimePrivateKeyParameters = null;
        try {
            // change the access from none/private to public
            Field[] formFields = privateKey.getClass().getDeclaredFields();
            if (formFields != null) {
                for (Field formField : formFields) {
                    // Necessary to be able to read a private field
                    formField.setAccessible(true);
                    Class type = formField.getType();
                    // how do I get the current value in this current object?
                    // Get the value of the field in the form object
                    Object fieldValue = formField.get(privateKey);
                    if (fieldValue instanceof org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters) {
                        ntrulpRimePrivateKeyParameters = (org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters) fieldValue;
                    }
                }
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        NTRULPRimeKEMExtractor kemExtractor = new NTRULPRimeKEMExtractor(ntrulpRimePrivateKeyParameters);
        return kemExtractor.extractSecret(secretToDecrypt);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}

