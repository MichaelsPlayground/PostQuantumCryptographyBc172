package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.rainbow.BCRainbowPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.rainbow.BCRainbowPublicKey;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PqcRainbowSignature {
    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
        // tested with BC version 1.71
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        System.out.println("PQC Rainbow signature");

        System.out.println("\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* Rainbow [signature]              *\n" +
                "* The program is using an OUTDATED *\n" +
                "* parameter set and I cannot       *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************");

        String dataToSignString = "The quick brown fox jumps over the lazy dog";
        byte[] dataToSign = dataToSignString.getBytes(StandardCharsets.UTF_8);

        // as there are 4 signature sets available the program runs all of them
        String[] rainbowSignatureSpecs = {
                "SHA224WITHRainbow",
                "SHA256WITHRainbow",
                "SHA384WITHRainbow",
                "SHA512WITHRainbow"
        };

        // statistics
        int nrOfSpecs = rainbowSignatureSpecs.length;
        String[] signatureSpecsName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] signatureLength = new int[nrOfSpecs];
        boolean[] signaturesVerified = new boolean[nrOfSpecs];

        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the Picnic key pair
            String signatureSpecName = rainbowSignatureSpecs[i];
            signatureSpecsName[i] = signatureSpecName;
            System.out.println("\nRainbow signature with signature set " + signatureSpecName);

            // generation of the Rainbow key pair
            KeyPair keyPair = generateRainbowKeyPair();

            // get private and public key
            PrivateKey privateKeyRainbow = keyPair.getPrivate();
            PublicKey publicKeyRainbow = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyRainbowByte = privateKeyRainbow.getEncoded();
            byte[] publicKeyRainbowByte = publicKeyRainbow.getEncoded();
            System.out.println("\ngenerated private key length: " + privateKeyRainbowByte.length);
            System.out.println("generated public key length:  " + publicKeyRainbowByte.length);
            privateKeyLength[i] = privateKeyRainbowByte.length;
            publicKeyLength[i] = publicKeyRainbowByte.length;;

            // generate the keys from a byte array
            PrivateKey privateKeyRainbowLoad = getBCRainbowPrivateKeyFromEncoded(privateKeyRainbowByte);
            PublicKey publicKeyRainbowLoad = getBCRainbowPublicKeyFromEncoded(publicKeyRainbowByte);

            System.out.println("\n* * * sign the dataToSign with the private key * * *");
            byte[] signature = pqcRainbowSignature(privateKeyRainbowLoad, dataToSign, signatureSpecName);
            System.out.println("signature length: " + signature.length + " data:\n" + bytesToHex(signature));
            signatureLength[i] = signature.length;

            System.out.println("\n* * * verify the signature with the public key * * *");
            boolean signatureVerified = pqcRainbowVerification(publicKeyRainbowLoad, dataToSign, signature, signatureSpecName);
            System.out.println("the signature is verified: " + signatureVerified);
            signaturesVerified[i] = signatureVerified;
        }

        System.out.println("\nTest results");
        System.out.println("parameter spec name  priKL   pubKL    sigL  sigV");
        for (int i = 0; i < nrOfSpecs; i++) {
            System.out.format("%-20s%6d%8d%8d%6b%n", signatureSpecsName[i], privateKeyLength[i], publicKeyLength[i], signatureLength[i], signaturesVerified[i]);
        }
        System.out.println("Legend: priKL privateKey length, pubKL publicKey length, sigL signature length, sigV signature verified\n");
    }

    private static KeyPair generateRainbowKeyPair() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("Rainbow");
            kpg.initialize(1024);
            //kpg.initialize(2048);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static BCRainbowPrivateKey getBCRainbowPrivateKeyFromEncoded(byte[] encodedKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Rainbow", "BCPQC");
            return (BCRainbowPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static BCRainbowPublicKey getBCRainbowPublicKeyFromEncoded(byte[] encodedKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Rainbow", "BCPQC");
            return (BCRainbowPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] pqcRainbowSignature(PrivateKey privateKey, byte[] dataToSign, String signatureHash) {
        Signature sig = null;
        try {
            sig = Signature.getInstance(signatureHash);
            sig.initSign(privateKey, new SecureRandom());
            sig.update(dataToSign, 0, dataToSign.length);
            return sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean pqcRainbowVerification(PublicKey publicKey, byte[] dataToSign, byte[] signature, String signatureHash) {
        Signature sigVerify = null;
        try {
            sigVerify = Signature.getInstance(signatureHash);
            sigVerify.initVerify(publicKey);
            sigVerify.update(dataToSign, 0, dataToSign.length);
            return sigVerify.verify(signature);
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