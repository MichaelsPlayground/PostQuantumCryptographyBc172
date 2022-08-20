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

public class PqcNtruPrimeKem {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
        // tested with BC version 1.71
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC NTRU Prime kem");

        System.out.println("\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* NTRU Prime                       *\n" +
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

        // data to encrypt is usually a 32 bytes long (randomly generated) AES key
        //String keyToEncryptString = "1234567890ABCDEF1122334455667788";
        //byte[] keyToEncrypt = keyToEncryptString.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the NTRU Prime key pair
            SNTRUPrimeParameters sntruPrimeParameter = sntruPrimeParameters[i];
            String ntruPrimeParameterSpecName = sntruPrimeParameter.getName();
            parameterSpecName[i] = ntruPrimeParameterSpecName;
            System.out.println("\nNTRU Prime KEM with parameterset " + ntruPrimeParameterSpecName);
            AsymmetricCipherKeyPair keyPair = generateNtruPrimeKeyPair(sntruPrimeParameter);

            // get private and public key
            AsymmetricKeyParameter privateKey = keyPair.getPrivate();
            AsymmetricKeyParameter publicKey = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyByte = ((SNTRUPrimePrivateKeyParameters) privateKey).getEncoded();
            byte[] privateKeyByteF = ((SNTRUPrimePrivateKeyParameters)privateKey).getF();
            byte[] privateKeyByteGinv = ((SNTRUPrimePrivateKeyParameters)privateKey).getGinv();
            byte[] privateKeyByteHash = ((SNTRUPrimePrivateKeyParameters)privateKey).getHash();
            byte[] privateKeyBytePk = ((SNTRUPrimePrivateKeyParameters)privateKey).getPk();
            byte[] privateKeyByteRho = ((SNTRUPrimePrivateKeyParameters)privateKey).getRho();
            byte[] publicKeyByte = ((SNTRUPrimePublicKeyParameters) publicKey).getEncoded();

            System.out.println("\ngenerated private key length: " + privateKeyByte.length);
            System.out.println("generated public key length:  " + publicKeyByte.length);
            privateKeyLength[i] = privateKeyByte.length;
            publicKeyLength[i] = publicKeyByte.length;
            // todo get key from encoded form

            /*
            System.out.println("A04 Auflistung aller Kryptographie-Provider und unterstützten Algorithmen");
            // source https://stackoverflow.com/questions/3683302/how-to-find-out-what-algorithm-encryption-are-supported-by-my-jvm/3683915#3683915
            for (Provider provider : Security.getProviders()) {
                System.out.println("Provider: " + provider.getName() + " version: " + provider.getVersion());
                for (Provider.Service service : provider.getServices()) {
                    System.out.printf("  Type: %-30s  Algorithm: %-30s\n", service.getType(), service.getAlgorithm());
                }
            }

             */

            // generate the keys from a byte array
            AsymmetricKeyParameter privateKeyLoad = (SNTRUPrimePrivateKeyParameters) getNtruPrimePrivateKeyFromEncoded(privateKeyByteF, privateKeyByteGinv, privateKeyBytePk, privateKeyByteRho, privateKeyByteHash, sntruPrimeParameter);
            AsymmetricKeyParameter publicKeyLoad = (SNTRUPrimePublicKeyParameters) getNtruPrimePublicKeyFromEncoded(publicKeyByte, sntruPrimeParameter);

            // generate the encryption key and the encapsulated key
            System.out.println("\nEncryption side: generate the encryption key");
            //byte[] encryptedKey = pqcNtruEncryptKey(publicKeyLoad, keyToEncrypt);
            SecretWithEncapsulation secretKeyWithEncapsulation = pqcNtruPrimeGenerateSecretWithEncapsulation(publicKeyLoad);
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
            //byte[] decryptedKey = pqcNtruDecryptKey(privateKeyLoad, encryptedKey);
            byte[] decryptedKey = pqcNtruPrimeExtractSecretWithEncapsulation(privateKeyLoad, encapsulatedKey);
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