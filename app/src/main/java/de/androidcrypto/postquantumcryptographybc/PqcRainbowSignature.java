package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.rainbow.BCRainbowPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.rainbow.BCRainbowPublicKey;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;

import java.nio.charset.StandardCharsets;
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

public class PqcRainbowSignature {
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

    public static String run(boolean truncateSignatureOutput) {
        String out = "PQC Rainbow signature (BC implementation)";

        out += "\n************************************\n" +
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
                "************************************";

        String dataToSignString = "The quick brown fox jumps over the lazy dog";
        byte[] dataToSign = dataToSignString.getBytes(StandardCharsets.UTF_8);

        // as there are 4 signature sets available the program runs all of them
/*
        RainbowParameterSpec[] specs =
                new RainbowParameterSpec[]
                        {
                                RainbowParameterSpec.rainbowIIIclassic,
                                RainbowParameterSpec.rainbowIIIcircumzenithal,
                                RainbowParameterSpec.rainbowIIIcompressed,
                                RainbowParameterSpec.rainbowVclassic,
                                RainbowParameterSpec.rainbowVcircumzenithal,
                                RainbowParameterSpec.rainbowVcompressed,
                        };
*/
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

        out += "\n\n****************************************\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the Rainbow key pair
            String signatureSpecName = rainbowSignatureSpecs[i];
            signatureSpecsName[i] = signatureSpecName;
            out += "\nRainbow signature with signature set " + signatureSpecName;

            // generation of the Rainbow key pair
            KeyPair keyPair = generateRainbowKeyPairOrg();

            // get private and public key
            PrivateKey privateKeyRainbow = keyPair.getPrivate();
            PublicKey publicKeyRainbow = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyRainbowByte = privateKeyRainbow.getEncoded();
            byte[] publicKeyRainbowByte = publicKeyRainbow.getEncoded();
            out += "\ngenerated private key length: " + privateKeyRainbowByte.length;
            out += "generated public key length:  " + publicKeyRainbowByte.length;
            privateKeyLength[i] = privateKeyRainbowByte.length;
            publicKeyLength[i] = publicKeyRainbowByte.length;;

            // generate the keys from a byte array
            PrivateKey privateKeyRainbowLoad = getRainbowPrivateKeyFromEncoded(privateKeyRainbowByte);
            PublicKey publicKeyRainbowLoad = getRainbowPublicKeyFromEncoded(publicKeyRainbowByte);

            out += "\n* * * sign the dataToSign with the private key * * *";
            byte[] signature = pqcRainbowSignature(privateKeyRainbowLoad, dataToSign, signatureSpecName);
            out += "signature length: " + signature.length + " data:\n" + bytesToHex(signature);
            signatureLength[i] = signature.length;

            out += "\n* * * verify the signature with the public key * * *";
            boolean signatureVerified = pqcRainbowVerification(publicKeyRainbowLoad, dataToSign, signature, signatureSpecName);
            out += "the signature is verified: " + signatureVerified;
            signaturesVerified[i] = signatureVerified;
            out += "\n\n****************************************\n";
        }

        out += "\nTest results";
        out += "parameter spec name  priKL   pubKL    sigL  sigV" + "\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            String out1 = String.format("%-20s%6d%8d%8d%6b%n", signatureSpecsName[i], privateKeyLength[i], publicKeyLength[i], signatureLength[i], signaturesVerified[i]);
            out += out1;
        }
        out += "Legend: priKL privateKey length, pubKL publicKey length, sigL signature length, sigV signature verified\n";
        out += "\n\n****************************************\n";
        return out;
    }

    // todo Rainbow parameters were introdused in Oct 26th 2022 and are not available in BC version 1.72
/*
    private static KeyPair generateRainbowKeyPairNew() {
        KeyPairGenerator kpg = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");

            kpg.initialize(RainbowParameterSpec.rainbowIIIclassic, new SecureRandom());

            KeyPair kp = kpg.generateKeyPair();


            kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
            kpg.initialize(1024);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }
*/
    private static KeyPair generateRainbowKeyPairOrg() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("Rainbow");
            kpg.initialize(1024);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PrivateKey getRainbowPrivateKeyFromEncoded(byte[] encodedKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Rainbow", "BCPQC");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PublicKey getRainbowPublicKeyFromEncoded(byte[] encodedKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("Rainbow", "BCPQC");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
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