package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionKeyGenerationParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionKeyPairGenerator;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEncryptionPublicKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.ntru.NTRUEngine;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

public class PqcNtruKem {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on
        // tested with BC version 1.72
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        String print = run(false);
        System.out.println(print);
    }

    public static String run(boolean truncateKeyOutput) {
        String out = "PQC NTRU KEM";

        out += "\n************************************\n" +
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
                "************************************";

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
        // short name of the parameters for the summary print out
        String[] ntruEncryptionKeyGenerationParameterNames = {
                "EES1087EP2",
                "EES1171EP1",
                "EES1499EP1",
                "APR2011_439",
                "APR2011_439_FAST",
                "APR2011_743",
                "APR2011_743_FAST"
        };

        // statistics
        int nrOfSpecs = ntruEncryptionKeyGenerationParameterSets.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] encryptedKeyLength = new int[nrOfSpecs];
        boolean[] encryptionKeysEquals = new boolean[nrOfSpecs];

        // data to encrypt is usually a 32 bytes long (randomly generated) AES key
        String keyToEncryptString = "1234567890ABCDEF1122334455667788";
        byte[] keyToEncrypt = keyToEncryptString.getBytes(StandardCharsets.UTF_8);

        out += "\n\n****************************************\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the NTRU key pair
            NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters = ntruEncryptionKeyGenerationParameterSets[i];
            String ntruParameterSpecName = ntruEncryptionKeyGenerationParameterNames[i];
            parameterSpecName[i] = ntruParameterSpecName;
            out += "\nNTRU KEM with parameterset " + ntruParameterSpecName;
            AsymmetricCipherKeyPair keyPair = generateNtruKeyPair(ntruEncryptionKeyGenerationParameters);

            // get private and public key
            AsymmetricKeyParameter privateKey = keyPair.getPrivate();
            AsymmetricKeyParameter publicKey = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyByte = ((NTRUEncryptionPrivateKeyParameters) privateKey).getEncoded();
            byte[] publicKeyByte = ((NTRUEncryptionPublicKeyParameters) publicKey).getEncoded();
            out += "\ngenerated private key length: " + privateKeyByte.length;
            out += "generated public key length:  " + publicKeyByte.length;
            privateKeyLength[i] = privateKeyByte.length;
            publicKeyLength[i] = publicKeyByte.length;

            // generate the keys from a byte array
            NTRUEncryptionPrivateKeyParameters privateKeyLoad = getNtruPrivateKeyFromEncoded(privateKeyByte, ntruEncryptionKeyGenerationParameters);
            NTRUEncryptionPublicKeyParameters publicKeyLoad = getNtruPublicKeyFromEncoded(publicKeyByte, ntruEncryptionKeyGenerationParameters);

            // generate the encryption key and the encapsulated key
            out += "\nEncryption side: generate the encryption key";
            byte[] encryptedKey = pqcNtruEncryptKey(publicKeyLoad, keyToEncrypt);
            out += "\n" + "encrypted key length: " + encryptedKey.length + " key: " + (truncateKeyOutput ?shortenString(bytesToHex(encryptedKey)):bytesToHex(encryptedKey));
            encryptedKeyLength[i] = encryptedKey.length;

            out += "\nDecryption side: receive the encrypted key and decrypt it to the decryption key";
            byte[] decryptedKey = pqcNtruDecryptKey(privateKeyLoad, encryptedKey);
            out += "\n" + "decrypted key length: " + decryptedKey.length + " key: " + (truncateKeyOutput ?shortenString(bytesToHex(decryptedKey)):bytesToHex(decryptedKey));
            boolean keysAreEqual = Arrays.areEqual(keyToEncrypt, decryptedKey);
            out += "decrypted key is equal to keyToEncrypt: " + keysAreEqual;
            encryptionKeysEquals[i] = keysAreEqual;
            out += "\n\n****************************************\n";
        }

        out += "\nTest results";
        out += "parameter spec name  priKL   pubKL encKL  keyE" + "\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            String out1 = String.format("%-20s%6d%8d%6d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], encryptedKeyLength[i], encryptionKeysEquals[i]);
            out += out1;
        }
        out += "\nLegend: priKL privateKey length, pubKL publicKey length, encKL encryption key length, keyE encryption keys are equal\n";
        out += "\n\n****************************************\n";
        return out;
    }

    private static String shortenString (String input) {
        if (input != null && input.length() > 32) {
            return input.substring(0, 32) + " ...";
        } else {
            return input;
        }
    }

    private static AsymmetricCipherKeyPair generateNtruKeyPair(NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters) {
        NTRUEncryptionKeyPairGenerator ntruEncryptionKeyPairGenerator = new NTRUEncryptionKeyPairGenerator();
        ntruEncryptionKeyPairGenerator.init(ntruEncryptionKeyGenerationParameters);
        AsymmetricCipherKeyPair kp = ntruEncryptionKeyPairGenerator.generateKeyPair();
        return kp;
    }

    private static byte[] pqcNtruEncryptKey(AsymmetricKeyParameter publicKey, byte[] keyToEncrypt) {
        NTRUEngine ntru = new NTRUEngine();
        ntru.init(true, publicKey);
        try {
            return ntru.processBlock(keyToEncrypt, 0, keyToEncrypt.length);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] pqcNtruDecryptKey(AsymmetricKeyParameter privateKey, byte[] encryptedKeyToDecrypt) {
        NTRUEngine ntru = new NTRUEngine();
        ntru.init(false, privateKey);
        try {
            return ntru.processBlock(encryptedKeyToDecrypt, 0, encryptedKeyToDecrypt.length);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKeyWithEncapsulation pqcGenerateNtruEncryptionKey(PublicKey publicKey) {
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

    private static NTRUEncryptionPrivateKeyParameters getNtruPrivateKeyFromEncoded(byte[] encodedKey, NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters) {
        NTRUEncryptionParameters ntruEncryptionParameters = ntruEncryptionKeyGenerationParameters.getEncryptionParameters();
        try {
            return new NTRUEncryptionPrivateKeyParameters(encodedKey, ntruEncryptionParameters);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static NTRUEncryptionPublicKeyParameters getNtruPublicKeyFromEncoded(byte[] encodedKey, NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters) {
        NTRUEncryptionParameters ntruEncryptionParameters = ntruEncryptionKeyGenerationParameters.getEncryptionParameters();
        return new NTRUEncryptionPublicKeyParameters(encodedKey, ntruEncryptionParameters);
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