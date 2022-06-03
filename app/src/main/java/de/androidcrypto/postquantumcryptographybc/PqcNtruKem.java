package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
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

public class PqcNtruKem {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
        // tested with BC version 1.71
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC NTRU kem");

        System.out.println("\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* NTRU [key exchange mechanism]    *\n" +
                "* The program is using an          *\n" +
                "* parameter set that I cannot      *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************");

        // as there are 7 parameter sets available the program runs all of them
        NTRUEncryptionKeyGenerationParameters[] ntruEncryptionKeyGenerationParameterSets = {
                NTRUEncryptionKeyGenerationParameters.EES1087EP2,
                NTRUEncryptionKeyGenerationParameters.EES1171EP1,
                NTRUEncryptionKeyGenerationParameters.EES1499EP1,
                NTRUEncryptionKeyGenerationParameters.APR2011_439,
                NTRUEncryptionKeyGenerationParameters.APR2011_439_FAST,
                NTRUEncryptionKeyGenerationParameters.APR2011_743,
                NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST
        };

        // statistics
        int nrOfSpecs = ntruEncryptionKeyGenerationParameterSets.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] encryptionKeyLength = new int[nrOfSpecs];
        int[] encapsulatedKeyLength = new int[nrOfSpecs];
        boolean[] encryptionKeysEquals = new boolean[nrOfSpecs];

        // data to encrypt is usually a 32 bytes long (randomly generated) AES key
        String keyToEncryptString = "1234567890ABCDEF1122334455667788";
        byte[] keyToEncrypt = keyToEncryptString.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the NTRU key pair
            NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters = ntruEncryptionKeyGenerationParameterSets[i];
            String ntruParameterSpecName = ntruEncryptionKeyGenerationParameters.toString();
            parameterSpecName[i] = ntruParameterSpecName;
            System.out.println("\nNTRU KEM with parameterset " + ntruParameterSpecName);
            AsymmetricCipherKeyPair keyPair = generateNtruKeyPair(ntruEncryptionKeyGenerationParameters);

            // get private and public key
            AsymmetricKeyParameter privateKey = keyPair.getPrivate();
            AsymmetricKeyParameter publicKey = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyByte = ((NTRUEncryptionPrivateKeyParameters) privateKey).getEncoded();
            byte[] publicKeyByte = ((NTRUEncryptionPublicKeyParameters) publicKey).getEncoded();
            System.out.println("\ngenerated private key length: " + privateKeyByte.length);
            System.out.println("generated public key length:  " + publicKeyByte.length);
            privateKeyLength[i] = privateKeyByte.length;
            publicKeyLength[i] = publicKeyByte.length;

            // generate the keys from a byte array
            PrivateKey privateKeyLoad = getFrodoPrivateKeyFromEncoded(privateKeyByte);
            PublicKey publicKeyLoad = getFrodoPublicKeyFromEncoded(publicKeyByte);

            // generate the encryption key and the encapsulated key
            System.out.println("\nEncryption side: generate the encryption key and the encapsulated key");
            SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = pqcGenerateFrodoEncryptionKey(publicKeyLoad);
            byte[] encryptionKey = secretKeyWithEncapsulationSender.getEncoded();
            System.out.println("encryption key length: " + encryptionKey.length
                    + " key: " + bytesToHex(secretKeyWithEncapsulationSender.getEncoded()));
            byte[] encapsulatedKey = secretKeyWithEncapsulationSender.getEncapsulation();
            System.out.println("encapsulated key length: " + encapsulatedKey.length + " key: " + bytesToHex(encapsulatedKey));
            encryptionKeyLength[i] = encryptionKey.length;
            encapsulatedKeyLength[i] = encapsulatedKey.length;

            System.out.println("\nDecryption side: receive the encapsulated key and generate the decryption key");
            byte[] decryptionKey = pqcGenerateFrodoDecryptionKey(privateKeyLoad, encapsulatedKey);
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

    private static AsymmetricCipherKeyPair generateNtruKeyPair(NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters) {
        NTRUEncryptionKeyPairGenerator ntruEncryptionKeyPairGenerator = new NTRUEncryptionKeyPairGenerator();
        ntruEncryptionKeyPairGenerator.init(ntruEncryptionKeyGenerationParameters);
        AsymmetricCipherKeyPair kp = ntruEncryptionKeyPairGenerator.generateKeyPair();
        return kp;
    }

    public static SecretKeyWithEncapsulation pqcGenerateFrodoEncryptionKey(PublicKey publicKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("Frodo", "BCPQC");
            keyGen.init(new KEMGenerateSpec((PublicKey) publicKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc1;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] pqcGenerateFrodoDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("Frodo", "BCPQC");
            keyGen.init(new KEMExtractSpec((PrivateKey) privateKey, encapsulatedKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc2.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PrivateKey getFrodoPrivateKeyFromEncoded(byte[] encodedKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Frodo", "BCPQC");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PublicKey getFrodoPublicKeyFromEncoded(byte[] encodedKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Frodo", "BCPQC");
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