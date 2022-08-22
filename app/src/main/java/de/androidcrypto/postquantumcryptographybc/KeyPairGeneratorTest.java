package de.androidcrypto.postquantumcryptographybc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public abstract class KeyPairGeneratorTest

{

    KeyPairGenerator kpg;

    KeyFactory kf;

    void performKeyPairEncodingTest(KeyPair keyPair)
    {
        try
        {
            PublicKey pubKey = keyPair.getPublic();
            PrivateKey privKey = keyPair.getPrivate();

            byte[] encPubKey = pubKey.getEncoded();
            byte[] encPrivKey = privKey.getEncoded();

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encPubKey);
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encPrivKey);

            PublicKey decPubKey = kf.generatePublic(pubKeySpec);
            PrivateKey decPrivKey = kf.generatePrivate(privKeySpec);

            System.out.println("publicKey is equal : " + Arrays.equals(pubKey.getEncoded(), decPubKey.getEncoded()));
            System.out.println("privateKey is equal: " + Arrays.equals(privKey.getEncoded(), decPrivKey.getEncoded()));
            //assertEquals(pubKey, decPubKey);
            //assertEquals(privKey, decPrivKey);

            checkSerialisation(pubKey);
            checkSerialisation(privKey);
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.out.println("fail: " + e);
            //fail(e);
        }
    }

    private void checkSerialisation(Key key)
            throws IOException, ClassNotFoundException
    {
        System.out.println("check serialisation");
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(key);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        Key keySer = (Key) oIn.readObject();
        System.out.println("publicKey is equal : " + Arrays.equals(key.getEncoded(), keySer.getEncoded()));
        //assertEquals(key, oIn.readObject());
    }

}