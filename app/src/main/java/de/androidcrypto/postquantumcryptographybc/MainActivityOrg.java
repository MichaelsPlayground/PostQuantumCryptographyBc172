package de.androidcrypto.postquantumcryptographybc;

import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256Signer;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.CMCEKey;
import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.cmce.BCCMCEPrivateKey;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.bouncycastle.util.Arrays;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;

import javax.crypto.KeyGenerator;

/* ##### place your imports here ##### */

public class MainActivityOrg extends AppCompatActivity {

    String consoleText = "";
    String APPTITLE = "change the application title here";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnClearConsole = findViewById(R.id.btnClearConsole);
        Button btnRunCode = findViewById(R.id.btnRunCode);

        btnClearConsole.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //
                TextView textViewConsole = (TextView) findViewById(R.id.textviewConsole);
                consoleText = "";
                textViewConsole.setText(consoleText);
            }
        });

        btnRunCode.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                clearConsole();
                runMain();
            }
        });
    }

    public void clearConsole() {
        consoleText = "";
        TextView textViewConsole = (TextView) findViewById(R.id.textviewConsole);
        textViewConsole.setText(consoleText);
        MainActivityOrg.this.setTitle(APPTITLE);
    }

    public void printlnX(String print) {
        consoleText = consoleText + print + "\n";
        TextView textViewConsole = (TextView) findViewById(R.id.textviewConsole);
        textViewConsole.setText(consoleText);
        System.out.println();
    }

    private static String getAndroidVersion() {
        String release = Build.VERSION.RELEASE;
        int sdkVersion = Build.VERSION.SDK_INT;
        return "Android SDK: " + sdkVersion + " (" + release + ")";
    }

    /* ############# your code comes below ####################
       change all code: System.out.println("something");
       to printlnX("something");
     */
    // place your main method here
    private void runMain() {

        // this way for adding bouncycastle to android
        Security.removeProvider("BC");
        // Confirm that positioning this provider at the end works for your needs!
        Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        printlnX("Android version: " + getAndroidVersion());
        printlnX("BouncyCastle version: " + getBouncyCastleVersion());
        printlnX("BouncyCastle PQC version: " + getBouncyCastlePqcVersion());

        /*
        // Bouncy Castle issue 1169 error decoding signature bytes (SHA512withECDSA) while verifying
        // https://github.com/bcgit/bc-java/issues/1169
        byte[] data1 = Hex.decode("4ba2a3ef661721d9a298d974a29f60d7e4551f47bd213b938ad5ad1e149d080f53392670854c88d62a35a1e8db4244dc46672a1a111dec95da42a3db2b16afae");
        byte[] publicKey1 = Hex.decode("30819b301006072a8648ce3d020106052b81040023038186000401fa9dc907b272ece7db51c9d1b4a78e27ef6657ec1c721eb681ee2018162b5d1ad92d5db71f8b21b91266c9b80f98c93ea29339b4af1fddcd824965e9144c36986b003432b3808243a2d4f9770c74f9d232bae27a1cf19a77726df7f28c86d02c0956203492667e41d10b601edadd1d2ef7ad4a5a4ed7166c1d1853bed303a419e32c13");
        byte[] signature1 = Hex.decode("308188024201d44cda9dc4f3bd2f501ae64b5115baa49797ded537fdc8bf7fdf6629aaaaf199511a63155c96846c7edaf0776a1dd5192e66ecdf41d38354b3cab7b286a59b7710024201036418b6b9b6e4ffe873220f0a2e7ab75fbea8df19f149ee8a6650624aba721b110059d35650484a6464bcb99cc7b4b9984dbdaeb198b7446c4951ccfea02df60c");

        byte[] data2 = Hex.decode("53742d9a35a0a563a89dbd4bfad6f8b052fa2313288f5dac258159724c0ba905b02a8e5701fff17ff0ccb009c5ea989ff496232ce5c7b299cc780a86280b3471");
        byte[] publicKey2 = Hex.decode("30819b301006072a8648ce3d020106052b81040023038186000401fa9dc907b272ece7db51c9d1b4a78e27ef6657ec1c721eb681ee2018162b5d1ad92d5db71f8b21b91266c9b80f98c93ea29339b4af1fddcd824965e9144c36986b003432b3808243a2d4f9770c74f9d232bae27a1cf19a77726df7f28c86d02c0956203492667e41d10b601edadd1d2ef7ad4a5a4ed7166c1d1853bed303a419e32c13");
        byte[] signature2 = Hex.decode("3081880242016f0c2b66d8b559631c682389fde37a13637f306abe53dd5e11283c82b980ad72c6e5ed7401bc8b71d5ec6ea16ad20a53d45b62ddb9b44fd0c0a1fa19fa4efbdaf40242000a1d45a4fab1110d2e569b3ebe4eccab0ef7d4d8252ce050e5454f33cf4e961e9c9dde84f190ca937f5ba1e9728ff624ed1ce624449dad132934f4bdb77213c63f");

        printlnX("validate dataset 1");
        try {
            printlnX(String.valueOf(validate(data1, signature1, publicKey1)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        printlnX("validate dataset 2");
        try {
            printlnX(String.valueOf(validate(data2, signature2, publicKey2)));
        } catch (Exception e) {
            e.printStackTrace();
            printlnX(e.toString());
        }
        */

        printlnX("");
        printlnX("*** SPHINX signature with BC start ***");

        String dataToSignString = "The quick brown fox jumps over the lazy dog";
        byte[] dataToSign = dataToSignString.getBytes(StandardCharsets.UTF_8);

        // generation of the Sphincs key pair
        // uses SHA3-256 for key generation
        AsymmetricCipherKeyPair keyPair = pqcGenerateSphincsKeyPairSha3();

        // get private and public key
        SPHINCSPrivateKeyParameters privateKey = (SPHINCSPrivateKeyParameters) keyPair.getPrivate();
        SPHINCSPublicKeyParameters publicKey = (SPHINCSPublicKeyParameters) keyPair.getPublic();

        // storing the key as byte array
        byte[] privateKeyEncoded = privateKey.getKeyData();
        byte[] publicKeyEncoded = publicKey.getKeyData();
        printlnX("\ngenerated private key length: " + privateKeyEncoded.length + " key algorithm: " + privateKey.getTreeDigest());
        printlnX("generated public key length:  " + publicKeyEncoded.length + " key algorithm: " + publicKey.getTreeDigest());

        // generate the keys from a byte array
        SPHINCSPrivateKeyParameters privateKeyLoad = new SPHINCSPrivateKeyParameters(privateKeyEncoded);
        SPHINCSPublicKeyParameters publicKeyLoad = new SPHINCSPublicKeyParameters(publicKeyEncoded);

        printlnX("\n* * * sign the dataToSign with the private key * * *");
        byte[] signature = pqcSphincsSignatureSha3(privateKeyLoad, dataToSign);
        printlnX("signature length: " + signature.length + " data: ** not shown due to length");

        printlnX("\n* * * verify the signature with the public key * * *");
        boolean signatureVerified = pqcSphincsVerificationSha3(publicKeyLoad, dataToSign, signature);
        printlnX("the signature is verified: " + signatureVerified);
        printlnX("");
        printlnX("*** SPHINX signature with BC end ***");
        printlnX("");

        printlnX("*** SPHINX Plus signature with BC start ***");

        //String dataToSignString = "The quick brown fox jumps over the lazy dog";
        //byte[] dataToSign = dataToSignString.getBytes(StandardCharsets.UTF_8);

        // generation of the Sphincs key pair
        // uses Shake256_256f for key generation
        KeyPair keyPairPlus = pqcGenerateSphincsPlusKeyPairShake256();

        // get private and public key
        PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
        PublicKey publicKeyPlus = keyPairPlus.getPublic();

        // storing the key as byte array
        byte[] privateKeyPlusEncoded = privateKeyPlus.getEncoded();
        byte[] publicKeyPlusEncoded = publicKeyPlus.getEncoded();
        printlnX("\ngenerated private key length: " + privateKeyPlusEncoded.length + " key algorithm: " + privateKeyPlus.getAlgorithm());
        printlnX("generated public key length:  " + publicKeyPlusEncoded.length + " key algorithm: " + publicKeyPlus.getAlgorithm());

        // generate the keys from a byte array
        KeyFactory keyFact = null;
        SPHINCSPlusKey sphincsPlusPrivateKey = null;
        SPHINCSPlusKey sphincsPlusPublicKey = null;
        try {
            keyFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
            sphincsPlusPrivateKey = (SPHINCSPlusKey) keyFact.generatePrivate(new PKCS8EncodedKeySpec(privateKeyPlusEncoded));
            sphincsPlusPublicKey = (SPHINCSPlusKey) keyFact.generatePublic(new X509EncodedKeySpec(publicKeyPlusEncoded));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

        printlnX("\n* * * sign the dataToSign with the private key * * *");
        //byte[] signaturePlus = pqcSphincsPlusSignature(privateKeyPlus, dataToSign);
        // this signature method runs with the private key recovered from encoded data
        byte[] signaturePlus = pqcSphincsPlusSignature(sphincsPlusPrivateKey, dataToSign);
        printlnX("signature length: " + signaturePlus.length + " data: ** not shown due to length");

        printlnX("\n* * * verify the signature with the public key * * *");
        //boolean signaturePlusVerified = pqcSphincsPlusVerification(publicKeyPlus, dataToSign, signaturePlus);
        // this signature verification method runs with the public key recovered from encoded data
        boolean signaturePlusVerified = pqcSphincsPlusVerification(sphincsPlusPublicKey, dataToSign, signaturePlus);
        printlnX("the signature is verified: " + signaturePlusVerified);
        printlnX("");
        printlnX("*** SPHINX Plus signature with BC end ***");
        printlnX("");

        printlnX("*** Classic McEliece KEM with BC start ***");

        CMCEParameterSpec[] cmceParameterSpecs = {
                CMCEParameterSpec.mceliece348864,
                CMCEParameterSpec.mceliece348864f,
                CMCEParameterSpec.mceliece460896,
                CMCEParameterSpec.mceliece6688128,
                CMCEParameterSpec.mceliece6960119,
                CMCEParameterSpec.mceliece8192128};
        for (int i = 0; i < cmceParameterSpecs.length; i++) {
            CMCEParameterSpec cmceParameterSpec = cmceParameterSpecs[i];

            printlnX("\nClassic McEliece with parameter " + cmceParameterSpec.getName());
            KeyPair keyPairClassicMcEliece = pqcGenerateClassicMcElieceKeyPair(cmceParameterSpec);

            BCCMCEPrivateKey bccmcePrivateKey = (BCCMCEPrivateKey) keyPairClassicMcEliece.getPrivate();
            //bccmcePrivateKey.getParameterSpec().getName()

            // get private and public key
            PrivateKey privateKeyClassicMcEliece = keyPairClassicMcEliece.getPrivate();
            PublicKey publicKeyClassicMcEliece = keyPairClassicMcEliece.getPublic();

            printlnX("generated private key length: " + privateKeyClassicMcEliece.getEncoded().length + " key algorithm: " + privateKeyClassicMcEliece.getAlgorithm());
            printlnX("generated public key length:  " + publicKeyClassicMcEliece.getEncoded().length + " key algorithm: " + publicKeyClassicMcEliece.getAlgorithm());
            printlnX(("difference private - public key: " + (privateKeyClassicMcEliece.getEncoded().length - publicKeyClassicMcEliece.getEncoded().length)));

            // send the public key to the sender to encrypt data
            printlnX("\nsend the public key to the sender to encrypt data");

            // generate the keys from a byte array
            KeyFactory keyFactCmce = null;
            PrivateKey cmcePrivateKey = null;
            PublicKey cmcePublicKey = null;
            try {
                keyFactCmce = KeyFactory.getInstance("CMCE", "BCPQC");
                cmcePrivateKey = keyFactCmce.generatePrivate(new PKCS8EncodedKeySpec(privateKeyClassicMcEliece.getEncoded()));
                cmcePublicKey = keyFactCmce.generatePublic(new X509EncodedKeySpec(publicKeyClassicMcEliece.getEncoded()));
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
                e.printStackTrace();
            }

            //CMCEKey cmcePrivateKey = null;
            //CMCEKey cmcePublicKey = null;
            /*
            try {
                keyFactCmce = KeyFactory.getInstance("CMCE", "BCPQC");
                cmcePrivateKey = (CMCEKey) keyFactCmce.generatePrivate(new PKCS8EncodedKeySpec(privateKeyClassicMcEliece.getEncoded()));
                cmcePublicKey = (CMCEKey) keyFactCmce.generatePublic(new X509EncodedKeySpec(publicKeyClassicMcEliece.getEncoded()));
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
                e.printStackTrace();
            }

             */

            // generate the encryption key and the encapsulated key
            printlnX("\nEncryption side: generate the encryption key and the encapsulated key");
            //SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = pqcGenerateClassicMcElieceEncryptionKey348864(publicKeyClassicMcEliece);
            //SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = pqcGenerateClassicMcElieceEncryptionKey348864(cmcePublicKey);
            SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = pqcGenerateClassicMcElieceEncryptionKey(cmcePublicKey);
            byte[] encyptionKey = secretKeyWithEncapsulationSender.getEncoded();
            printlnX("encryption key length: " + encyptionKey.length
                    + " key: " + bytesToHex(secretKeyWithEncapsulationSender.getEncoded()));
            byte[] encapsulatedKey = secretKeyWithEncapsulationSender.getEncapsulation();
            printlnX("encapsulated key length: " + encapsulatedKey.length + " key: " + bytesToHex(encapsulatedKey));

            printlnX("\nDecryption side: receive the encapsulated key and generate the decryption key");
            //byte[] decryptionKey = pqcGenerateClassicMcElieceDecryptionKey(privateKeyClassicMcEliece, encapsulatedKey);
            //byte[] decryptionKey = pqcGenerateClassicMcElieceDecryptionKey(cmcePrivateKey, encapsulatedKey);
            byte[] decryptionKey = pqcGenerateClassicMcElieceDecryptionKey2(cmcePrivateKey, encapsulatedKey);
            printlnX("decryption key length: " + decryptionKey.length + " key: " + bytesToHex(decryptionKey));
            boolean keysAreEqual = Arrays.areEqual(encyptionKey, decryptionKey);
            printlnX("decryption key is equal to encryption key: " + keysAreEqual);
        }
        printlnX("\n*** Classic McEliece KEM with BC end ***");

    }

    private static String getBouncyCastleVersion() {
        Provider provider = Security.getProvider("BC");
        return String.valueOf(provider.getVersion());
    }

    private static String getBouncyCastlePqcVersion() {
        Provider provider = Security.getProvider("BCPQC");
        return String.valueOf(provider.getVersion());
    }

    private static boolean validate(byte[] data, byte[] signature, byte[] publicKey) throws Exception {
        Provider provider = new BouncyCastleProvider();
        Signature signer = Signature.getInstance("SHA512withECDSA", provider);

        //PublicKey pb = KeyFactory.getInstance("ECDSA", provider).generatePublic(new X509EncodedKeySpec(publicKey));
        //System.out.println("*** pb: " + pb.getAlgorithm() + " Format: " + pb.getFormat());

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey pb = keyFactory.generatePublic(publicKeySpec);

        signer.initVerify(pb);
        signer.update(data);
        return signer.verify(signature);
    }

    public static AsymmetricCipherKeyPair pqcGenerateSphincsKeyPairSha3() {
        SPHINCS256KeyPairGenerator generator = new SPHINCS256KeyPairGenerator();
        generator.init(new SPHINCS256KeyGenerationParameters(new SecureRandom(), new SHA3Digest(256)));
        AsymmetricCipherKeyPair kp = generator.generateKeyPair();
        return kp;
    }

    public static byte[] pqcSphincsSignatureSha3(SPHINCSPrivateKeyParameters priv, byte[] messageByte) {
        MessageSigner sphincsSigner = new SPHINCS256Signer(new SHA3Digest(256), new SHA3Digest(512));
        sphincsSigner.init(true, priv);
        byte[] sig = sphincsSigner.generateSignature(messageByte);
        return sig;
    }

    public static Boolean pqcSphincsVerificationSha3(SPHINCSPublicKeyParameters pub, byte[] messageByte, byte[] signatureByte) {
        MessageSigner sphincsSigner = new SPHINCS256Signer(new SHA3Digest(256), new SHA3Digest(512));
        sphincsSigner.init(false, pub);
        return sphincsSigner.verifySignature(messageByte, signatureByte);
    }


    /**
     * Sphincs Plus methods
     */

    public static KeyPair pqcGenerateSphincsPlusKeyPairShake256() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
            //kpg.initialize(SPHINCSPlusParameterSpec.sha256_128f, new SecureRandom());
            //kpg.initialize(SPHINCSPlusParameterSpec.shake256_256f, new SecureRandom()); // Beta 02
            kpg.initialize(SPHINCSPlusParameterSpec.shake_256f, new SecureRandom()); // Beta 10
            KeyPair kp = kpg.generateKeyPair();
            return kp;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    //public static byte[] pqcSphincsPlusSignature(PrivateKey privateKey, byte[] messageByte) {
    public static byte[] pqcSphincsPlusSignature(SPHINCSPlusKey privateKey, byte[] messageByte) {
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
    public static Boolean pqcSphincsPlusVerification(SPHINCSPlusKey publicKey, byte[] messageByte, byte[] signatureByte) {
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

    /**
     * Classic McEliece methods
     */

    public static KeyPair pqcGenerateClassicMcElieceKeyPair(CMCEParameterSpec cmceParameterSpec) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
            kpg.initialize(cmceParameterSpec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            return kp;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    //public static byte[][] pqcGenerateClassicMcElieceEncryptionKey348864(PublicKey publicKey) {
    public static SecretKeyWithEncapsulation pqcGenerateClassicMcElieceEncryptionKey348864(CMCEKey publicKey) {
        //public static SecretKeyWithEncapsulation pqcGenerateClassicMcElieceEncryptionKey348864(PublicKey publicKey) {
        // output: [0] = key encapsulation
        // output: [1] = encoded key
        KeyGenerator keyGen = null;
        //byte[][] output = new byte[2][];
        try {
            keyGen = KeyGenerator.getInstance("CMCE", "BCPQC");
            keyGen.init(new KEMGenerateSpec((PublicKey) publicKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc1;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKeyWithEncapsulation pqcGenerateClassicMcElieceEncryptionKey(PublicKey publicKey) {
        // output: [0] = key encapsulation
        // output: [1] = encoded key
        KeyGenerator keyGen = null;
        //byte[][] output = new byte[2][];
        try {
            keyGen = KeyGenerator.getInstance("CMCE", "BCPQC");
            keyGen.init(new KEMGenerateSpec((PublicKey) publicKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc1;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] pqcGenerateClassicMcElieceDecryptionKey2(PrivateKey privateKey, byte[] encapsulatedKey) {
        //public static byte[] pqcGenerateClassicMcElieceDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("CMCE", "BCPQC");
            keyGen.init(new KEMExtractSpec((PrivateKey) privateKey, encapsulatedKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc2.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] pqcGenerateClassicMcElieceDecryptionKey(CMCEKey privateKey, byte[] encapsulatedKey) {
    //public static byte[] pqcGenerateClassicMcElieceDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey) {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("CMCE", "BCPQC");
            keyGen.init(new KEMExtractSpec((PrivateKey) privateKey, encapsulatedKey, "AES"), new SecureRandom());
            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation) keyGen.generateKey();
            return secEnc2.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }


    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private static String getTimestampFormatted() {
        // java.time is available from SDK 26+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            DateTimeFormatter dtf = null;
            dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss");
            LocalDateTime now = LocalDateTime.now();
            return dtf.format(now);
        } else {
            DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            Calendar cal = Calendar.getInstance();
            return dateFormat.format(cal.getTime());
        }
    }
}