package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.util.Arrays;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

public class PqcClassicMcElieceKem {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
        // tested with BC version 1.71
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        String print = run(false);
        System.out.println(print);
        
        System.out.println("PQC Classic McEliece kem");

        System.out.println("\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm Classic Mc     *\n" +
                "* Eliece [key exchange mechanism]  *\n" +
                "* The program is using an          *\n" +
                "* parameter set that I cannot      *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************");

        // as there are 6 parameter sets available the program runs all of them
        CMCEParameterSpec[] cmceParameterSpecs = {
                CMCEParameterSpec.mceliece348864,
                CMCEParameterSpec.mceliece348864f,
                CMCEParameterSpec.mceliece460896,
                CMCEParameterSpec.mceliece6688128,
                CMCEParameterSpec.mceliece6960119,
                CMCEParameterSpec.mceliece8192128};

        // statistics
        int nrOfSpecs = cmceParameterSpecs.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] encryptionKeyLength = new int[nrOfSpecs];
        int[] encapsulatedKeyLength = new int[nrOfSpecs];
        boolean[] encryptionKeysEquals = new boolean[nrOfSpecs];

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the Classic McEliece key pair
            CMCEParameterSpec cmceParameterSpec = cmceParameterSpecs[i];
            String cmceParameterSpecName = cmceParameterSpec.getName();
            parameterSpecName[i] = cmceParameterSpecName;
            System.out.println("\nClassic McEliece KEM with parameterset " + cmceParameterSpecName);
            KeyPair keyPair = generateClassicMcElieceKeyPair(cmceParameterSpec);

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
            PrivateKey privateKeyLoad = getClassicMcEliecePrivateKeyFromEncoded(privateKeyByte);
            PublicKey publicKeyLoad = getClassicMcEliecePublicKeyFromEncoded(publicKeyByte);

            // generate the encryption key and the encapsulated key
            System.out.println("\nEncryption side: generate the encryption key and the encapsulated key");
            SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = pqcGenerateClassicMcElieceEncryptionKey(publicKeyLoad);
            byte[] encryptionKey = secretKeyWithEncapsulationSender.getEncoded();
            System.out.println("encryption key length: " + encryptionKey.length
                    + " key: " + bytesToHex(secretKeyWithEncapsulationSender.getEncoded()));
            byte[] encapsulatedKey = secretKeyWithEncapsulationSender.getEncapsulation();
            System.out.println("encapsulated key length: " + encapsulatedKey.length + " key: " + bytesToHex(encapsulatedKey));
            encryptionKeyLength[i] = encryptionKey.length;
            encapsulatedKeyLength[i] = encapsulatedKey.length;

            System.out.println("\nDecryption side: receive the encapsulated key and generate the decryption key");
            byte[] decryptionKey = pqcGenerateClassicMcElieceDecryptionKey(privateKeyLoad, encapsulatedKey);
            System.out.println("decryption key length: " + decryptionKey.length + " key: " + bytesToHex(decryptionKey));
            boolean keysAreEqual = Arrays.areEqual(encryptionKey, decryptionKey);
            System.out.println("decryption key is equal to encryption key: " + keysAreEqual);
            encryptionKeysEquals[i] = keysAreEqual;
        }

        System.out.println("\nTest results");
        System.out.println("parameter spec name     priKL    pubKL encKL capKL  keyE");
        for (int i = 0; i < nrOfSpecs; i++) {
            System.out.format("%-20s%9d%9d%6d%6d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], encryptionKeyLength[i], encapsulatedKeyLength[i], encryptionKeysEquals[i]);
        }
        System.out.println("Legend: priKL privateKey length, pubKL publicKey length, encKL encryption key length, capKL encrapsulated key length, keyE encryption keys are equal\n");
    }

    public static String run(boolean truncateKeyOutput) {
        String out = "PQC Classic McEliece KEM";

        out += "\n" + "\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm Classic Mc     *\n" +
                "* Eliece [key exchange mechanism]  *\n" +
                "* The program is using an          *\n" +
                "* parameter set that I cannot      *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************";

        // as there are 6 parameter sets available the program runs all of them
        CMCEParameterSpec[] cmceParameterSpecs = {
                CMCEParameterSpec.mceliece348864,
                CMCEParameterSpec.mceliece348864f,
                CMCEParameterSpec.mceliece460896,
                CMCEParameterSpec.mceliece6688128,
                CMCEParameterSpec.mceliece6960119,
                CMCEParameterSpec.mceliece8192128};

        // statistics
        int nrOfSpecs = cmceParameterSpecs.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] encryptionKeyLength = new int[nrOfSpecs];
        int[] encapsulatedKeyLength = new int[nrOfSpecs];
        boolean[] encryptionKeysEquals = new boolean[nrOfSpecs];

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the Classic McEliece key pair
            CMCEParameterSpec cmceParameterSpec = cmceParameterSpecs[i];
            String cmceParameterSpecName = cmceParameterSpec.getName();
            parameterSpecName[i] = cmceParameterSpecName;
            out += "\n" + "\nClassic McEliece KEM with parameterset " + cmceParameterSpecName;
            KeyPair keyPair = generateClassicMcElieceKeyPair(cmceParameterSpec);

            // get private and public key
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyByte = privateKey.getEncoded();
            byte[] publicKeyByte = publicKey.getEncoded();
            out += "\n" + "\ngenerated private key length: " + privateKeyByte.length;
            out += "\n" + "generated public key length:  " + publicKeyByte.length;
            privateKeyLength[i] = privateKeyByte.length;
            publicKeyLength[i] = publicKeyByte.length;

            // generate the keys from a byte array
            PrivateKey privateKeyLoad = getClassicMcEliecePrivateKeyFromEncoded(privateKeyByte);
            PublicKey publicKeyLoad = getClassicMcEliecePublicKeyFromEncoded(publicKeyByte);

            // generate the encryption key and the encapsulated key
            out += "\n" + "\nEncryption side: generate the encryption key and the encapsulated key";
            SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = pqcGenerateClassicMcElieceEncryptionKey(publicKeyLoad);
            byte[] encryptionKey = secretKeyWithEncapsulationSender.getEncoded();
            out += "\n" + "encryption key length: " + encryptionKey.length
                    + " key: " + bytesToHex(secretKeyWithEncapsulationSender.getEncoded());
            byte[] encapsulatedKey = secretKeyWithEncapsulationSender.getEncapsulation();
            out += "\n" + "encapsulated key length: " + encapsulatedKey.length + " key: " + (truncateKeyOutput ?shortenString(bytesToHex(encapsulatedKey)):bytesToHex(encapsulatedKey));
            encryptionKeyLength[i] = encryptionKey.length;
            encapsulatedKeyLength[i] = encapsulatedKey.length;

            out += "\n" + "\nDecryption side: receive the encapsulated key and generate the decryption key";
            byte[] decryptionKey = pqcGenerateClassicMcElieceDecryptionKey(privateKeyLoad, encapsulatedKey);
            out += "\n" + "decryption key length: " + decryptionKey.length + " key: " + bytesToHex(decryptionKey);
            boolean keysAreEqual = Arrays.areEqual(encryptionKey, decryptionKey);
            out += "\n" + "decryption key is equal to encryption key: " + keysAreEqual;
            encryptionKeysEquals[i] = keysAreEqual;
        }

        out += "\n" + "\nTest results";
        out += "\n" + "parameter spec name     priKL    pubKL encKL capKL  keyE" + "\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            String out1 = String.format("%-20s%9d%9d%6d%6d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], encryptionKeyLength[i], encapsulatedKeyLength[i], encryptionKeysEquals[i]);
            out += out1;
        }
        out += "\n" + "Legend: priKL privateKey length, pubKL publicKey length, encKL encryption key length, capKL encapsulated key length, keyE encryption keys are equal\n";
        return out;
    }

    private static String shortenString(String input) {
        if (input != null && input.length() > 32) {
            return input.substring(0, 32) + " ...";
        } else {
            return input;
        }
    }
    
    public static KeyPair generateClassicMcElieceKeyPair(CMCEParameterSpec cmceParameterSpec) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
            kpg.initialize(cmceParameterSpec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            return kp;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKeyWithEncapsulation pqcGenerateClassicMcElieceEncryptionKey(PublicKey publicKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("CMCE", "BCPQC");
            keyGen.init(new KEMGenerateSpec((PublicKey) publicKey, "AES"), new SecureRandom());
            return (SecretKeyWithEncapsulation) keyGen.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] pqcGenerateClassicMcElieceDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("CMCE", "BCPQC");
            keyGen.init(new KEMExtractSpec((PrivateKey) privateKey, encapsulatedKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc2.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PrivateKey getClassicMcEliecePrivateKeyFromEncoded(byte[] encodedKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("CMCE", "BCPQC");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PublicKey getClassicMcEliecePublicKeyFromEncoded(byte[] encodedKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("CMCE", "BCPQC");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}