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
import org.bouncycastle.util.Arrays;

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

public class PqcNtruLPRimeReflectionKem {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
        // tested with BC version 1.72 Beta 13
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC NTRU LPRime kem (Reflection)");
        System.out.println("This program builds the Private and Public Keys using Reflection");
        System.out.println("WARNING: this program may not work in every environment due to restrictions, so do NOT USE IT in production !");

        System.out.println("\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* NTRULPRime                       *\n" +
                "* [key exchange mechanism]         *\n" +
                "* The program is using an          *\n" +
                "* parameter set that I cannot      *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************");

        // as there are 6 parameter sets available the program runs all of them
        NTRULPRimeParameters[] ntruLPrimeParameters = new NTRULPRimeParameters[] {
                NTRULPRimeParameters.ntrulpr653,
                NTRULPRimeParameters.ntrulpr761,
                NTRULPRimeParameters.ntrulpr857,
                NTRULPRimeParameters.ntrulpr953,
                NTRULPRimeParameters.ntrulpr1013,
                NTRULPRimeParameters.ntrulpr1277
        };

        // statistics
        int nrOfSpecs = ntruLPrimeParameters.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] encryptedKeyLength = new int[nrOfSpecs];
        boolean[] encryptionKeysEquals = new boolean[nrOfSpecs];

        // data to encrypt is usually a 32 bytes long (randomly generated) AES key
        //String keyToEncryptString = "1234567890ABCDEF1122334455667788";
        //byte[] keyToEncrypt = keyToEncryptString.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the NTRU Prime key pair
            NTRULPRimeParameters ntruLPrimeParameter = ntruLPrimeParameters[i];
            String ntruPrimeParameterSpecName = ntruLPrimeParameter.getName();
            parameterSpecName[i] = ntruPrimeParameterSpecName;
            System.out.println("\nNTRU Prime KEM with parameterset " + ntruPrimeParameterSpecName);
            AsymmetricCipherKeyPair keyPair = generateNtruLPRimeKeyPair(ntruLPrimeParameter);

            // get private and public key
            AsymmetricKeyParameter privateKeyOriginal = keyPair.getPrivate();
            AsymmetricKeyParameter publicKeyOriginal = keyPair.getPublic();

            // convert the key to a BCNTRULPRimePrivateKey / PublicKey
            PrivateKeyInfo privateKeyInfoOriginal = null;
            SubjectPublicKeyInfo subjectPublicKeyInfoOriginal = null;
            BCNTRULPRimePrivateKey privateKeyLoadN = null;
            BCNTRULPRimePublicKey publicKeyLoadN = null;
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

                System.out.println("\ngenerated private key length: " + bcntrulpRimePrivateKeyOriginalByte.length);
                System.out.println("generated public key length:  " + bcntrulpRimePublicKeyOriginalByte.length);
                privateKeyLength[i] = bcntrulpRimePrivateKeyOriginalByte.length;
                publicKeyLength[i] = bcntrulpRimePublicKeyOriginalByte.length;
            } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
                e.printStackTrace();
            }

            // generate the encryption key and the encapsulated key
            System.out.println("\nEncryption side: generate the encryption key");
            SecretWithEncapsulation secretKeyWithEncapsulation = pqcNtruLPRimeGenerateSecretWithEncapsulationR(publicKeyLoadN);
            //SecretWithEncapsulation secretKeyWithEncapsulation = pqcNtruLPRimeGenerateSecretWithEncapsulation(publicKeyLoad);
            // this is the encryption key for e.g. aes encryption
            byte[] encryptionKey = secretKeyWithEncapsulation.getSecret();
            System.out.println("encryption key length: " + encryptionKey.length
                    + " key: " + bytesToHex(encryptionKey));
            // this is the encapsulated key that is send to the receiver
            byte[] encapsulatedKey = secretKeyWithEncapsulation.getEncapsulation();
            encryptedKeyLength[i] = encapsulatedKey.length;
            System.out.println("encapsulated key length: " + encapsulatedKey.length
                    + " key: " + bytesToHex(encapsulatedKey));

            System.out.println("\nDecryption side: receive the encapsulated key and decrypt it to the decryption key");
            byte[] decryptedKey = pqcNtruLRimeExtractSecretWithEncapsulationR(privateKeyLoadN, encapsulatedKey);
            //byte[] decryptedKey = pqcNtruLRimeExtractSecretWithEncapsulation(privateKeyLoad, encapsulatedKey);
            System.out.println("decryption key length: " + decryptedKey.length + " key: " + bytesToHex(decryptedKey));
            boolean keysAreEqual = Arrays.areEqual(encryptionKey, decryptedKey);
            System.out.println("decrypted key is equal to keyToEncrypt: " + keysAreEqual);
            encryptionKeysEquals[i] = keysAreEqual;
        }

        System.out.println("\nTest results");
        System.out.println("parameter spec name  priKL   pubKL encKL  keyE");
        for (int i = 0; i < nrOfSpecs; i++) {
             System.out.format("%-20s%6d%8d%6d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], encryptedKeyLength[i], encryptionKeysEquals[i]);
        }
        System.out.println("Legend: priKL privateKey length, pubKL publicKey length, encKL encryption key length, keyE encryption keys are equal\n");
    }

    private static AsymmetricCipherKeyPair generateNtruLPRimeKeyPair(NTRULPRimeParameters ntruLPrimeParameter) {
        NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
        keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(new SecureRandom(), ntruLPrimeParameter));
        AsymmetricCipherKeyPair kp = keyPairGenerator.generateKeyPair();
        return kp;
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

    private static SecretWithEncapsulation pqcNtruLPRimeGenerateSecretWithEncapsulation(AsymmetricKeyParameter publicKey) {
        NTRULPRimeKEMGenerator kemGenerator = new NTRULPRimeKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(publicKey);
        return secretEncapsulation;
    }

    private static byte[] pqcNtruLRimeExtractSecretWithEncapsulation(AsymmetricKeyParameter privateKey, byte[] secretToDecrypt) {
        NTRULPRimeKEMExtractor kemExtractor = new NTRULPRimeKEMExtractor((NTRULPRimePrivateKeyParameters) privateKey);
        return kemExtractor.extractSecret(secretToDecrypt);
    }

    private static AsymmetricKeyParameter getNtruLPRimePrivateKeyFromEncoded(byte[] enca, byte[] pk, byte[] rho, byte[] hash, NTRULPRimeParameters ntruLPrimeParameter) {
        return new NTRULPRimePrivateKeyParameters(ntruLPrimeParameter, enca, pk, rho, hash);
    }

    private static AsymmetricKeyParameter getNtruLPRimePublicKeyFromEncoded(byte[] encodedKey, NTRULPRimeParameters ntruLPrimeParameter) {
        return new NTRULPRimePublicKeyParameters(ntruLPrimeParameter, encodedKey);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}