package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FrodoParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;
import org.bouncycastle.util.Arrays;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

public class PqcSaberKem {


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException, InvalidKeySpecException {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
        // tested with BC version 1.71
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC Saber kem");

        System.out.println("\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* SABER [key exchange mechanism]   *\n" +
                "* The program is using an          *\n" +
                "* parameter set that I cannot      *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************");

        // as there are 9 parameter sets available the program runs all of them
        SABERParameterSpec[] saberParameterSpecs =  {
                SABERParameterSpec.lightsaberkem128r3,
                SABERParameterSpec.saberkem128r3,
                SABERParameterSpec.firesaberkem128r3,
                SABERParameterSpec.lightsaberkem192r3,
                SABERParameterSpec.saberkem192r3,
                SABERParameterSpec.firesaberkem192r3,
                SABERParameterSpec.lightsaberkem256r3,
                SABERParameterSpec.saberkem256r3,
                SABERParameterSpec.firesaberkem256r3
        };

        // statistics
        int nrOfSpecs = saberParameterSpecs.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] encryptionKeyLength = new int[nrOfSpecs];
        int[] encapsulatedKeyLength = new int[nrOfSpecs];
        boolean[] encryptionKeysEquals = new boolean[nrOfSpecs];

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the SABER key pair
            SABERParameterSpec saberParameterSpec = saberParameterSpecs[i];
            String saberParameterSpecName = saberParameterSpec.getName();
            parameterSpecName[i] = saberParameterSpecName;
            System.out.println("\nSABER KEM with parameterset " + saberParameterSpecName);
            KeyPair keyPair = generateSaberKeyPair(saberParameterSpec);

            // get private and public key
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyByte = privateKey.getEncoded();
            byte[] publicKeyByte = publicKey.getEncoded();
            System.out.println("\ngenerated private key length: " + privateKeyByte.length);
            System.out.println("generated public key length:  " + publicKeyByte.length);
            privateKeyLength[i] = privateKeyByte.length;
            publicKeyLength[i] = publicKeyByte.length;

            // generate the keys from a byte array
            PrivateKey privateKeyLoad = getSaberPrivateKeyFromEncoded(privateKeyByte);
            PublicKey publicKeyLoad = getSaberPublicKeyFromEncoded(publicKeyByte);

            // generate the encryption key and the encapsulated key
            System.out.println("\nEncryption side: generate the encryption key and the encapsulated key");
            SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = pqcGenerateSaberEncryptionKey(publicKeyLoad);
            byte[] encryptionKey = secretKeyWithEncapsulationSender.getEncoded();
            System.out.println("encryption key length: " + encryptionKey.length
                    + " key: " + bytesToHex(secretKeyWithEncapsulationSender.getEncoded()));
            byte[] encapsulatedKey = secretKeyWithEncapsulationSender.getEncapsulation();
            System.out.println("encapsulated key length: " + encapsulatedKey.length + " key: " + bytesToHex(encapsulatedKey));
            encryptionKeyLength[i] = encryptionKey.length;
            encapsulatedKeyLength[i] = encapsulatedKey.length;

            System.out.println("\nDecryption side: receive the encapsulated key and generate the decryption key");
            byte[] decryptionKey = pqcGenerateSaberDecryptionKey(privateKeyLoad, encapsulatedKey);
            System.out.println("decryption key length: " + decryptionKey.length + " key: " + bytesToHex(decryptionKey));
            boolean keysAreEqual = Arrays.areEqual(encryptionKey, decryptionKey);
            System.out.println("decryption key is equal to encryption key: " + keysAreEqual);
            encryptionKeysEquals[i] = keysAreEqual;
        }

        System.out.println("\nTest results");
        System.out.println("parameter spec name  priKL   pubKL encKL capKL  keyE");
        for (int i = 0; i < nrOfSpecs; i++) {
             System.out.format("%-20s%6d%8d%6d%6d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], encryptionKeyLength[i], encapsulatedKeyLength[i], encryptionKeysEquals[i]);
        }
        System.out.println("Legend: priKL privateKey length, pubKL publicKey length, encKL encryption key length, capKL encrapsulated key length, keyE encryption keys are equal\n");
    }

    private static KeyPair generateSaberKeyPair(SABERParameterSpec saberParameterSpec) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SABER", "BCPQC");
            kpg.initialize(saberParameterSpec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            return kp;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKeyWithEncapsulation pqcGenerateSaberEncryptionKey(PublicKey publicKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("SABER", "BCPQC");
            keyGen.init(new KEMGenerateSpec((PublicKey) publicKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc1;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] pqcGenerateSaberDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("SABER", "BCPQC");
            keyGen.init(new KEMExtractSpec((PrivateKey) privateKey, encapsulatedKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc2.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PrivateKey getSaberPrivateKeyFromEncoded(byte[] encodedKey)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("SABER", "BCPQC");
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    private static PublicKey getSaberPublicKeyFromEncoded(byte[] encodedKey)
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("SABER", "BCPQC");
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}