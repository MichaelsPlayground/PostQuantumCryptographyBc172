package de.androidcrypto.postquantumcryptographybc;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.interfaces.DilithiumPrivateKeySpec;
import net.thiim.dilithium.interfaces.DilithiumPublicKeySpec;
import net.thiim.dilithium.provider.DilithiumProvider;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;

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

public class PqcChrystalsDilithiumMthiimSignature {

    // THIS IS NOT CHRYSTALS-DILITHIUM from BC - it is not available in BC Beta 10
    // source for the library is: https://github.com/mthiim/dilithium-java

    public static void main(String[] args) {

        DilithiumProvider provider = new DilithiumProvider();
        Security.addProvider(provider);


        System.out.println("PQC Chrystals Dilithium signature");

        System.out.println("\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* Chrystals Dilithium [signature]  *\n" +
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

        // as there are 3 parameter sets available the program runs all of them
        DilithiumParameterSpec[] dilithiumParameterSpecs =  {
                DilithiumParameterSpec.LEVEL2,
                DilithiumParameterSpec.LEVEL3,
                DilithiumParameterSpec.LEVEL5
        };

        // statistics
        int nrOfSpecs = dilithiumParameterSpecs.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] signatureLength = new int[nrOfSpecs];
        boolean[] signaturesVerified = new boolean[nrOfSpecs];

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the Chrystals Dilithium key pair
            DilithiumParameterSpec dilithiumParameterSpec = dilithiumParameterSpecs[i];
            String dilithiumParameterSpecName = dilithiumParameterSpec.name;
            parameterSpecName[i] = dilithiumParameterSpecName;
            System.out.println("\nPicnic signature with parameterset " + dilithiumParameterSpecName);
            KeyPair keyPair = generateChrystalsDilithiumKeyPair(dilithiumParameterSpec);

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
            PrivateKey privateKeyLoad = getChrystalsDilithiumPrivateKeyFromEncoded(dilithiumParameterSpec, privateKeyByte);
            PublicKey publicKeyLoad = getChrystalsDilithiumPublicKeyFromEncoded(dilithiumParameterSpec, publicKeyByte);

            System.out.println("\n* * * sign the dataToSign with the private key * * *");
            byte[] signature = pqcChrystalsDilithiumSignature(privateKeyLoad, dataToSign);
            System.out.println("signature length: " + signature.length + " data:\n" + bytesToHex(signature));
            signatureLength[i] = signature.length;

            System.out.println("\n* * * verify the signature with the public key * * *");
            boolean signatureVerified = pqcChrystalsDilithiumVerification(publicKeyLoad, dataToSign, signature);
            System.out.println("the signature is verified: " + signatureVerified);
            signaturesVerified[i] = signatureVerified;
        }

        System.out.println("\nTest results");
        System.out.println("parameter spec name          priKL   pubKL    sigL  sigV");
        for (int i = 0; i < nrOfSpecs; i++) {
            System.out.format("%-20s%6d%8d%8d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], signatureLength[i], signaturesVerified[i]);
        }
        System.out.println("Legend: priKL privateKey length, pubKL publicKey length, sigL signature length, sigV signature verified\n");
    }

    private static KeyPair generateChrystalsDilithiumKeyPair(DilithiumParameterSpec dilithiumParameterSpec) {
        try {
            SecureRandom sr = new SecureRandom();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
            kpg.initialize(dilithiumParameterSpec, sr);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PrivateKey getChrystalsDilithiumPrivateKeyFromEncoded(DilithiumParameterSpec dilithiumParameterSpec, byte[] encodedKey) {
        DilithiumPrivateKeySpec dilithiumPrivateKeySpec = new DilithiumPrivateKeySpec(dilithiumParameterSpec, encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Dilithium");
            return keyFactory.generatePrivate(dilithiumPrivateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PublicKey getChrystalsDilithiumPublicKeyFromEncoded(DilithiumParameterSpec dilithiumParameterSpec, byte[] encodedKey) {
        DilithiumPublicKeySpec dilithiumPublicKeySpec = new DilithiumPublicKeySpec(dilithiumParameterSpec, encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Dilithium");
            return keyFactory.generatePublic(dilithiumPublicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] pqcChrystalsDilithiumSignature(PrivateKey privateKey, byte[] dataToSign) {
        try {
            Signature sig = Signature.getInstance("Dilithium");
            sig.initSign((PrivateKey) privateKey, new SecureRandom());
            sig.update(dataToSign, 0, dataToSign.length);
            byte[] signature = sig.sign();
            return signature;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean pqcChrystalsDilithiumVerification(PublicKey publicKey, byte[] dataToSign, byte[] signature) {
        try {
            Signature sig = Signature.getInstance("Dilithium");
            sig.initVerify((PublicKey) publicKey);
            sig.update(dataToSign, 0, dataToSign.length);
            boolean result = sig.verify(signature);
            return result;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
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