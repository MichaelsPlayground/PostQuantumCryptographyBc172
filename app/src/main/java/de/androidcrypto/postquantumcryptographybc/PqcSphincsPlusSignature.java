package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.nio.charset.StandardCharsets;
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
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PqcSphincsPlusSignature {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
        // tested with BC version 1.68
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC Sphincs Plus signature");

        System.out.println("\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* Sphincs Plus [signature]         *\n" +
                "* The program is using an          *\n" +
                "* parameter set that I cannot      *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************");

        String dataToSignString = "The quick brown fox jumps over the lazy dog";
        byte[] dataToSign = dataToSignString.getBytes(StandardCharsets.UTF_8);

        // as there are 24 parameter sets available the program runs all of them
        SPHINCSPlusParameterSpec[] sphincsPlusParameterSpecs = {
                SPHINCSPlusParameterSpec.sha2_128f,
                SPHINCSPlusParameterSpec.sha2_128f_simple,
                SPHINCSPlusParameterSpec.sha2_128s,
                SPHINCSPlusParameterSpec.sha2_128s_simple,
                SPHINCSPlusParameterSpec.sha2_192f,
                SPHINCSPlusParameterSpec.sha2_192f_simple,
                SPHINCSPlusParameterSpec.sha2_192s,
                SPHINCSPlusParameterSpec.sha2_192s_simple,
                SPHINCSPlusParameterSpec.sha2_256f,
                SPHINCSPlusParameterSpec.sha2_256f_simple,
                SPHINCSPlusParameterSpec.sha2_256s,
                SPHINCSPlusParameterSpec.sha2_256s_simple,
                SPHINCSPlusParameterSpec.shake_128f,
                SPHINCSPlusParameterSpec.shake_128f_simple,
                SPHINCSPlusParameterSpec.shake_128s,
                SPHINCSPlusParameterSpec.shake_128s_simple,
                SPHINCSPlusParameterSpec.shake_192f,
                SPHINCSPlusParameterSpec.shake_192f_simple,
                SPHINCSPlusParameterSpec.shake_192s,
                SPHINCSPlusParameterSpec.shake_192s_simple,
                SPHINCSPlusParameterSpec.shake_256f,
                SPHINCSPlusParameterSpec.shake_256f_simple,
                SPHINCSPlusParameterSpec.shake_256s,
                SPHINCSPlusParameterSpec.shake_256s_simple
        };

        // statistics
        int nrOfSpecs = sphincsPlusParameterSpecs.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] signatureLength = new int[nrOfSpecs];
        boolean[] signaturesVerified = new boolean[nrOfSpecs];

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the Sphincs Plus key pair
            SPHINCSPlusParameterSpec sphincsPlusParameterSpec = sphincsPlusParameterSpecs[i];
            String sphincsPlusParameterSpecName = sphincsPlusParameterSpec.getName();
            parameterSpecName[i] = sphincsPlusParameterSpecName;
            System.out.println("\nSphincs Plus signature with parameterset " + sphincsPlusParameterSpecName);
            // generation of the SphincsPlus key pair
            KeyPair keyPair = generateSphincsPlusKeyPair(sphincsPlusParameterSpec);

            // get private and public key
            PrivateKey privateKeySphincsPlus = keyPair.getPrivate();
            PublicKey publicKeySphincsPlus = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeySphincsPlusByte = privateKeySphincsPlus.getEncoded();
            byte[] publicKeySphincsPlusByte = publicKeySphincsPlus.getEncoded();
            System.out.println("\ngenerated private key length: " + privateKeySphincsPlusByte.length);
            System.out.println("generated public key length:  " + publicKeySphincsPlusByte.length);
            privateKeyLength[i] = privateKeySphincsPlusByte.length;
            publicKeyLength[i] = publicKeySphincsPlusByte.length;

            // generate the keys from a byte array
            PrivateKey privateKeySphincsPlusLoad = getSphincsPlusPrivateKeyFromEncoded(privateKeySphincsPlusByte);
            PublicKey publicKeySphincsPlusLoad = getSphincsPlusPublicKeyFromEncoded(publicKeySphincsPlusByte);

            System.out.println("\n* * * sign the dataToSign with the private key * * *");
            byte[] signature = pqcSphincsPlusSignature(privateKeySphincsPlusLoad, dataToSign);
            System.out.println("signature length: " + signature.length + " data:\n" + bytesToHex(signature));
            signatureLength[i] = signature.length;

            System.out.println("\n* * * verify the signature with the public key * * *");
            boolean signatureVerified = pqcSphincsPlusVerification(publicKeySphincsPlusLoad, dataToSign, signature);
            System.out.println("the signature is verified: " + signatureVerified);
            signaturesVerified[i] = signatureVerified;
        }

        System.out.println("\nTest results");
        System.out.println("parameter spec name  priKL   pubKL    sigL  sigV");
        for (int i = 0; i < nrOfSpecs; i++) {
            System.out.format("%-20s%6d%8d%8d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], signatureLength[i], signaturesVerified[i]);
        }
        System.out.println("Legend: priKL privateKey length, pubKL publicKey length, sigL signature length, sigV signature verified\n");
    }

    private static KeyPair generateSphincsPlusKeyPair(SPHINCSPlusParameterSpec sphincsPlusParameterSpec) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
            kpg.initialize(sphincsPlusParameterSpec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            return kp;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    //public static byte[] pqcSphincsPlusSignature(PrivateKey privateKey, byte[] messageByte) {
    private static byte[] pqcSphincsPlusSignature(SPHINCSPlusKey privateKey, byte[] messageByte) {
        try {
            Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
            sig.initSign((PrivateKey) privateKey, new SecureRandom());
            sig.update(messageByte, 0, messageByte.length);
            byte[] signature = sig.sign();
            return signature;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    //public static Boolean pqcSphincsPlusVerification(PublicKey publicKey, byte[] messageByte, byte[] signatureByte) {
    private static Boolean pqcSphincsPlusVerification(SPHINCSPlusKey publicKey, byte[] messageByte, byte[] signatureByte) {
        try {
            Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
            sig.initVerify((PublicKey) publicKey);
            sig.update(messageByte, 0, messageByte.length);
            boolean result = sig.verify(signatureByte);
            return result;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }


    private static PrivateKey getSphincsPlusPrivateKeyFromEncoded(byte[] encodedKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PublicKey getSphincsPlusPublicKeyFromEncoded(byte[] encodedKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] pqcSphincsPlusSignature(PrivateKey privateKey, byte[] dataToSign) {
        try {
            Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
            sig.initSign((PrivateKey) privateKey, new SecureRandom());
            sig.update(dataToSign, 0, dataToSign.length);
            return sig.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean pqcSphincsPlusVerification(PublicKey publicKey, byte[] dataToSign, byte[] signature) {
        try {
            Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");
            sig.initVerify((PublicKey) publicKey);
            sig.update(dataToSign, 0, dataToSign.length);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}