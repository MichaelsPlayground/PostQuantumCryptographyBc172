package de.androidcrypto.postquantumcryptographybc;

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
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;

import java.security.SecureRandom;
import java.security.Security;

public class PqcNtruLPRimeKem {


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
        String out = "PQC NTRU LPRime kem)";

        out += "\n************************************\n" +
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
                "************************************";

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

        out += "\n\n****************************************\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the NTRU Prime key pair
            NTRULPRimeParameters ntruLPrimeParameter = ntruLPrimeParameters[i];
            String ntruPrimeParameterSpecName = ntruLPrimeParameter.getName();
            parameterSpecName[i] = ntruPrimeParameterSpecName;
            out += "\nNTRU Prime KEM with parameterset " + ntruPrimeParameterSpecName;
            AsymmetricCipherKeyPair keyPair = generateNtruLPRimeKeyPair(ntruLPrimeParameter);

            // get private and public key
            AsymmetricKeyParameter privateKey = keyPair.getPrivate();
            AsymmetricKeyParameter publicKey = keyPair.getPublic();

            // storing the key as byte array
            // todo find a better way to rebuild the keys from the encoded form
            byte[] privateKeyByte = ((NTRULPRimePrivateKeyParameters) privateKey).getEncoded();
            byte[] privateKeyByteEnca = ((NTRULPRimePrivateKeyParameters)privateKey).getEnca();
            byte[] privateKeyBytePk = ((NTRULPRimePrivateKeyParameters)privateKey).getPk();
            byte[] privateKeyByteHash = ((NTRULPRimePrivateKeyParameters)privateKey).getHash();
            byte[] privateKeyByteRho = ((NTRULPRimePrivateKeyParameters)privateKey).getRho();
            byte[] publicKeyByte = ((NTRULPRimePublicKeyParameters) publicKey).getEncoded();

            out += "\ngenerated private key length: " + privateKeyByte.length;
            out += "generated public key length:  " + publicKeyByte.length;
            privateKeyLength[i] = privateKeyByte.length;
            publicKeyLength[i] = publicKeyByte.length;
            // generate the keys from a byte array
            AsymmetricKeyParameter publicKeyLoad = getNtruLPRimePublicKeyFromEncoded(publicKeyByte, ntruLPrimeParameter);
            AsymmetricKeyParameter privateKeyLoad = getNtruLPRimePrivateKeyFromEncoded(privateKeyByteEnca, privateKeyBytePk, privateKeyByteRho, privateKeyByteHash, ntruLPrimeParameter);

            // generate the encryption key and the encapsulated key
            out += "\nEncryption side: generate the encryption key";
            SecretWithEncapsulation secretKeyWithEncapsulation = pqcNtruLPRimeGenerateSecretWithEncapsulation(publicKeyLoad);
            // this is the encryption key for e.g. aes encryption
            byte[] encryptionKey = secretKeyWithEncapsulation.getSecret();
            out += "encryption key length: " + encryptionKey.length
                    + " key: " + bytesToHex(encryptionKey);
            // this is the encapsulated key that is send to the receiver
            byte[] encapsulatedKey = secretKeyWithEncapsulation.getEncapsulation();
            encryptedKeyLength[i] = encapsulatedKey.length;
            out += "\n" + "encapsulated key length: " + encapsulatedKey.length + " key: " + (truncateKeyOutput ?shortenString(bytesToHex(encapsulatedKey)):bytesToHex(encapsulatedKey));
            out += "\nDecryption side: receive the encapsulated key and decrypt it to the decryption key";
            byte[] decryptedKey = pqcNtruLRimeExtractSecretWithEncapsulation(privateKeyLoad, encapsulatedKey);
            out += "decryption key length: " + decryptedKey.length + " key: " + bytesToHex(decryptedKey);
            boolean keysAreEqual = Arrays.areEqual(encryptionKey, decryptedKey);
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
        out += "\n****************************************\n";
        return out;
    }

    private static String shortenString (String input) {
        if (input != null && input.length() > 32) {
            return input.substring(0, 32) + " ...";
        } else {
            return input;
        }
    }

    private static AsymmetricCipherKeyPair generateNtruLPRimeKeyPair(NTRULPRimeParameters ntruLPrimeParameter) {
        NTRULPRimeKeyPairGenerator keyPairGenerator = new NTRULPRimeKeyPairGenerator();
        keyPairGenerator.init(new NTRULPRimeKeyGenerationParameters(new SecureRandom(), ntruLPrimeParameter));
        AsymmetricCipherKeyPair kp = keyPairGenerator.generateKeyPair();
        return kp;
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