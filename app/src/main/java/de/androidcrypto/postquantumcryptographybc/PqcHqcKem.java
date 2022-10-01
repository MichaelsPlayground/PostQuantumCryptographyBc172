package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;

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

public class PqcHqcKem {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
        // tested with BC version 1.72
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        String print = run(false);
        System.out.println(print);
    }

    public static String run(boolean truncateKeyOutput) {
        String out = "PQC HQC KEM";

        out += "\n" + "\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* HQC [key exchange mechanism]     *\n" +
                "* The program is using an          *\n" +
                "* parameter set that I cannot      *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************";

        // as there are 3 parameter sets available the program runs all of them
        HQCParameters[] hqcParameters = {
                HQCParameters.hqc128,
                HQCParameters.hqc192,
                HQCParameters.hqc256
        };

        // statistics
        int nrOfSpecs = hqcParameters.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] encryptionKeyLength = new int[nrOfSpecs];
        int[] encapsulatedKeyLength = new int[nrOfSpecs];
        boolean[] encryptionKeysEquals = new boolean[nrOfSpecs];

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the HQC key pair
            HQCParameters hqcParameter = hqcParameters[i];
            String hqcParameterSpecName = hqcParameter.getName();
            parameterSpecName[i] = hqcParameterSpecName;
            out += "\n" + "\nHQC KEM with parameterset " + hqcParameterSpecName;
            AsymmetricCipherKeyPair keyPair = generateHqcKeyPair(hqcParameter);

            // get private and public key
            AsymmetricKeyParameter privateKey = keyPair.getPrivate();
            AsymmetricKeyParameter publicKey = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyByte = ((HQCPrivateKeyParameters) privateKey).getEncoded();
            byte[] publicKeyByte = ((HQCPublicKeyParameters) publicKey).getEncoded();
            out += "\n" + "\ngenerated private key length: " + privateKeyByte.length;
            out += "\n" + "generated public key length:  " + publicKeyByte.length;
            privateKeyLength[i] = privateKeyByte.length;
            publicKeyLength[i] = publicKeyByte.length;

            // generate the keys from a byte array
            HQCPrivateKeyParameters privateKeyLoad = new HQCPrivateKeyParameters(hqcParameter, privateKeyByte);
            HQCPublicKeyParameters publicKeyLoad = new HQCPublicKeyParameters(hqcParameter, publicKeyByte);

            // generate the encryption key and the encapsulated key
            out += "\n" + "\nEncryption side: generate the encryption key and the encapsulated key";
            SecretWithEncapsulation secretWithEncapsulationSender = pqcGenerateHqcEncryptionKey(publicKeyLoad);
            byte[] encryptionKey = secretWithEncapsulationSender.getSecret();
            out += "\n" + "encryption key length: " + encryptionKey.length
                    + " key: " + bytesToHex(encryptionKey);
            byte[] encapsulatedKey = secretWithEncapsulationSender.getEncapsulation();
            out += "\n" + "encapsulated key length: " + encapsulatedKey.length + " key: " + (truncateKeyOutput ? shortenString(bytesToHex(encapsulatedKey)) : bytesToHex(encapsulatedKey));
            encryptionKeyLength[i] = encryptionKey.length;
            encapsulatedKeyLength[i] = encapsulatedKey.length;

            out += "\n" + "\nDecryption side: receive the encapsulated key and generate the decryption key";
            byte[] decryptionKey = pqcGenerateHqcDecryptionKey(privateKeyLoad, encapsulatedKey);
            out += "\n" + "decryption key length: " + decryptionKey.length + " key: " + bytesToHex(decryptionKey);
            boolean keysAreEqual = Arrays.areEqual(encryptionKey, decryptionKey);
            out += "\n" + "decryption key is equal to encryption key: " + keysAreEqual;
            encryptionKeysEquals[i] = keysAreEqual;
        }

        out += "\n" + "\nTest results";
        out += "\n" + "parameter spec name  priKL   pubKL encKL capKL  keyE" + "\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            String out1 = String.format("%-20s%6d%8d%6d%6d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], encryptionKeyLength[i], encapsulatedKeyLength[i], encryptionKeysEquals[i]);
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

    private static AsymmetricCipherKeyPair generateHqcKeyPair(HQCParameters hqcParameters) {
        HQCKeyPairGenerator hqcKeyGen = new HQCKeyPairGenerator();
        HQCKeyGenerationParameters genParam = new HQCKeyGenerationParameters(new SecureRandom(), hqcParameters);
        hqcKeyGen.init(genParam);
        AsymmetricCipherKeyPair kp = hqcKeyGen.generateKeyPair();
        return kp;
    }

    public static SecretWithEncapsulation pqcGenerateHqcEncryptionKey(HQCPublicKeyParameters publicKey) {
        HQCKEMGenerator hqcKemGenerator = new HQCKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretWithEnc = hqcKemGenerator.generateEncapsulated(publicKey);
        return secretWithEnc;
    }

    public static byte[] pqcGenerateHqcDecryptionKey(HQCPrivateKeyParameters privateKey, byte[] encapsulatedKey) {
        HQCKEMExtractor hqcKemExtractor = new HQCKEMExtractor(privateKey);
        byte[] dec_key = hqcKemExtractor.extractSecret(encapsulatedKey);
        return dec_key;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}