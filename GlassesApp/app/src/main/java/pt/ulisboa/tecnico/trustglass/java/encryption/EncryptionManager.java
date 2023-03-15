package pt.ulisboa.tecnico.trustglass.java.encryption;

import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

class Message {
    public String header;
    public String msg;
    public String sig;
    public String fresh;
}

public class EncryptionManager {
    private String key = "";
    private KeyPair sessionKeyPair = null;
    private PublicKey peerKey = null;

    private SecretKey symKey = null;

    public String processMessage(String text) {
        Gson gson = new Gson();
        Message msg = gson.fromJson(text, Message.class);

        //If in handshake step
        if (msg.header.equals("HANDSHAKE")) {
            key = msg.msg;
            byte[] decodedKey = Base64.decode(msg.msg, Base64.DEFAULT);
            peerKey = ecPointToPublicKey(new String(decodedKey));
            sessionKeyPair = generateECKeyPair();
            if (peerKey == null || sessionKeyPair == null) {
                return "Handshake ERROR\nFailed to either generate the session keys or retrieve the peer key";
            }
            symKey = generateSharedSecret(sessionKeyPair.getPrivate(), peerKey);
            if (symKey == null) {
                return "Handshake ERROR\nFailed to generate Shared Key";
            }
            String key = Base64.encodeToString(symKey.getEncoded(), Base64.DEFAULT);

            //No wrap simplifies the debug process (no need to hand write codes or copy-paste 76 characters at a time)
            ECPublicKey ecPubKey = (ECPublicKey) sessionKeyPair.getPublic();
            ECPoint publicPoint = ecPubKey.getW();
            Log.d("pointX:", publicPoint.getAffineX().toString(16));
            Log.d("pointY:", publicPoint.getAffineY().toString(16));
            String outputHex = "04" + publicPoint.getAffineX().toString(16) + publicPoint.getAffineY().toString(16);
            String pubKeyToSend = Base64.encodeToString(outputHex.getBytes(), Base64.NO_WRAP);
            Log.d("SecretKeyBase64:", key);
            Log.d("PubKeyToSend", pubKeyToSend);
            return "Handshake OK\nWrite the following key in the keyboard:\n" + pubKeyToSend;
        }

        //Decrypt

        //Check authenticity

        //Check freshness

        //Display message
        return msg.msg;
    }

    public KeyPair generateECKeyPair() {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");

            kpGen.initialize(new ECGenParameterSpec("prime256v1"));
            return kpGen.generateKeyPair();

//            return "OK";
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private ECPublicKey ecPointToPublicKey(String hexECPoint) {
        if (!hexECPoint.startsWith("04")) {
            throw new RuntimeException("Wrong hex EC Point format");
        }
        String xCoord = hexECPoint.substring(2, 66);
        String yCoord = hexECPoint.substring(66);
        if (xCoord.length() != yCoord.length()) {
            throw new RuntimeException("Wrong hex EC Point coordinate split");
        }

        ECPoint pubPoint = new ECPoint(new BigInteger(xCoord, 16),new BigInteger(yCoord, 16));
        AlgorithmParameters parameters = null;
        try {
            parameters = AlgorithmParameters.getInstance("EC");

            parameters.init(new ECGenParameterSpec("prime256v1"));
            ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return (ECPublicKey)kf.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidParameterSpecException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKey generateSharedSecret(PrivateKey privateKey,
                                           PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            SecretKey key = keyAgreement.generateSecret("AES");
            return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            return null;
        }
    }
}
