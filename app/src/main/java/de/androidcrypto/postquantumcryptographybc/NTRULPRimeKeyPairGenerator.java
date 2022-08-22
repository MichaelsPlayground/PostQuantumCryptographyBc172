package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec;

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
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * KeyFactory/KeyPairGenerator tests for NTRULPRime with BCPQC provider.
 */
public class NTRULPRimeKeyPairGenerator
        extends KeyPairGenerator
{

    protected NTRULPRimeKeyPairGenerator(String algorithm) {
        super(algorithm);
    }

    public void testKeyFactory()
            throws Exception
    {
        kf = KeyFactory.getInstance("NTRULPRime", "BCPQC");
        kf = KeyFactory.getInstance(BCObjectIdentifiers.pqc_kem_frodo.getId(), "BCPQC");
    }

    public void runKeyPairEncoding()
            throws Exception
    {
        NTRULPRimeParameterSpec[] specs =
                new NTRULPRimeParameterSpec[]
                        {
                                NTRULPRimeParameterSpec.ntrulpr653,
                                NTRULPRimeParameterSpec.ntrulpr761,
                                NTRULPRimeParameterSpec.ntrulpr857,
                                NTRULPRimeParameterSpec.ntrulpr953,
                                NTRULPRimeParameterSpec.ntrulpr1013,
                                NTRULPRimeParameterSpec.ntrulpr1277
                        };
        kf = KeyFactory.getInstance("NTRULPRime", "BCPQC");

        kpg = KeyPairGenerator.getInstance("NTRULPRime", "BCPQC");

        for (int i = 0; i != specs.length; i++)
        {
            System.out.println("testing " + specs[i].getName());
            kpg.initialize(specs[i], new SecureRandom());
            performKeyPairEncoding(kpg.generateKeyPair());
        }
    }

    java.security.KeyPairGenerator kpg;

    KeyFactory kf;

    void performKeyPairEncoding(KeyPair keyPair)
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