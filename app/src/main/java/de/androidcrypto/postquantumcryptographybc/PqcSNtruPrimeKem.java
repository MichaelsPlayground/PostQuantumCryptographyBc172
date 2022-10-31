package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.BCSNTRUPrimePrivateKey;
import org.bouncycastle.util.Arrays;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PqcSNtruPrimeKem {

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
    // todo system.out nach out umstellen
    public static String run(boolean truncateKeyOutput) {
        String out = "PQC SNTRU Prime kem (streamlined NTRUPrime)";

        out += "\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* SNTRU Prime                       *\n" +
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
        SNTRUPrimeParameters[] sntruPrimeParameters = new SNTRUPrimeParameters[] {
                        SNTRUPrimeParameters.sntrup653,
                        SNTRUPrimeParameters.sntrup761,
                        SNTRUPrimeParameters.sntrup857,
                        SNTRUPrimeParameters.sntrup953,
                        SNTRUPrimeParameters.sntrup1013,
                        SNTRUPrimeParameters.sntrup1277
                };

        // statistics
        int nrOfSpecs = sntruPrimeParameters.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] encryptedKeyLength = new int[nrOfSpecs];
        boolean[] encryptionKeysEquals = new boolean[nrOfSpecs];

        out += "\n\n****************************************\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the NTRU Prime key pair
            SNTRUPrimeParameters sntruPrimeParameter = sntruPrimeParameters[i];
            String ntruPrimeParameterSpecName = sntruPrimeParameter.getName();
            parameterSpecName[i] = ntruPrimeParameterSpecName;
            out += "\nSNTRU Prime KEM with parameterset " + ntruPrimeParameterSpecName;
            AsymmetricCipherKeyPair keyPair = generateNtruPrimeKeyPair(sntruPrimeParameter);

            // get private and public key
            AsymmetricKeyParameter privateKey = keyPair.getPrivate();
            AsymmetricKeyParameter publicKey = keyPair.getPublic();

            // storing the key as byte array
            // todo find a better way to rebuild the keys from the encoded form
            byte[] privateKeyByte = ((SNTRUPrimePrivateKeyParameters) privateKey).getEncoded();
            byte[] privateKeyByteF = ((SNTRUPrimePrivateKeyParameters)privateKey).getF();
            byte[] privateKeyByteGinv = ((SNTRUPrimePrivateKeyParameters)privateKey).getGinv();
            byte[] privateKeyByteHash = ((SNTRUPrimePrivateKeyParameters)privateKey).getHash();
            byte[] privateKeyBytePk = ((SNTRUPrimePrivateKeyParameters)privateKey).getPk();
            byte[] privateKeyByteRho = ((SNTRUPrimePrivateKeyParameters)privateKey).getRho();
            byte[] publicKeyByte = ((SNTRUPrimePublicKeyParameters) publicKey).getEncoded();

            out += "\ngenerated private key length: " + privateKeyByte.length;
            out += "generated public key length:  " + publicKeyByte.length;
            privateKeyLength[i] = privateKeyByte.length;
            publicKeyLength[i] = publicKeyByte.length;

            // generate the keys from a byte array
            AsymmetricKeyParameter privateKeyLoad = (SNTRUPrimePrivateKeyParameters) getNtruPrimePrivateKeyFromEncoded(privateKeyByteF, privateKeyByteGinv, privateKeyBytePk, privateKeyByteRho, privateKeyByteHash, sntruPrimeParameter);
            AsymmetricKeyParameter publicKeyLoad = (SNTRUPrimePublicKeyParameters) getNtruPrimePublicKeyFromEncoded(publicKeyByte, sntruPrimeParameter);

            // generate the encryption key and the encapsulated key
            out += "\nEncryption side: generate the encryption key";
            SecretWithEncapsulation secretKeyWithEncapsulation = pqcNtruPrimeGenerateSecretWithEncapsulation(publicKeyLoad);
            // this is the encryption key for e.g. aes encryption
            byte[] encryptionKey = secretKeyWithEncapsulation.getSecret();
            out += "encryption key length: " + encryptionKey.length
                    + " key: " + bytesToHex(encryptionKey);
            // this is the encapsulated key that is send to the receiver
            byte[] encapsulatedKey = secretKeyWithEncapsulation.getEncapsulation();
            encryptedKeyLength[i] = encapsulatedKey.length;
            out += "\n" + "encapsulated key length: " + encapsulatedKey.length + " key: " + (truncateKeyOutput ?shortenString(bytesToHex(encapsulatedKey)):bytesToHex(encapsulatedKey));
            out += "\nDecryption side: receive the encapsulated key and decrypt it to the decryption key";
            byte[] decryptedKey = pqcNtruPrimeExtractSecretWithEncapsulation(privateKeyLoad, encapsulatedKey);
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
        out += "Legend: priKL privateKey length, pubKL publicKey length, encKL encryption key length, keyE encryption keys are equal\n";
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

    private static AsymmetricCipherKeyPair generateNtruPrimeKeyPair(SNTRUPrimeParameters sntruPrimeParameter) {
        SNTRUPrimeKeyPairGenerator keyPairGenerator = new SNTRUPrimeKeyPairGenerator();
        keyPairGenerator.init(new SNTRUPrimeKeyGenerationParameters(new SecureRandom(), sntruPrimeParameter));
        AsymmetricCipherKeyPair kp = keyPairGenerator.generateKeyPair();
        return kp;
    }

    private static SecretWithEncapsulation pqcNtruPrimeGenerateSecretWithEncapsulation(AsymmetricKeyParameter publicKey) {
        SNTRUPrimeKEMGenerator kemGenerator = new SNTRUPrimeKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(publicKey);
        return secretEncapsulation;
    }

    private static byte[] pqcNtruPrimeExtractSecretWithEncapsulation(AsymmetricKeyParameter privateKey, byte[] secretToDecrypt) {
        SNTRUPrimeKEMExtractor kemExtractor = new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters)privateKey);
        return kemExtractor.extractSecret(secretToDecrypt);
    }

    private static AsymmetricKeyParameter getNtruPrimePrivateKeyFromEncoded(byte[] f, byte[] ginv, byte[] pk, byte[] rho, byte[] hash, SNTRUPrimeParameters sntruPrimeParameter) {
        return new SNTRUPrimePrivateKeyParameters(sntruPrimeParameter, f, ginv, pk, rho, hash);
    }

    private static AsymmetricKeyParameter getNtruPrimePublicKeyFromEncoded(byte[] encodedKey, SNTRUPrimeParameters sntruPrimeParameter) {
        return new SNTRUPrimePublicKeyParameters(sntruPrimeParameter, encodedKey);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}