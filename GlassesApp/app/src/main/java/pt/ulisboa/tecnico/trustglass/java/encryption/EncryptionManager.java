package pt.ulisboa.tecnico.trustglass.java.encryption;

import android.content.Context;
import android.os.Environment;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import pt.ulisboa.tecnico.trustglass.BuildConfig;

class Handshake {
    public String key;
    public Map<String, String> map;
}

class MessageContent {
    public String hdr;
    public String msg;

    public Map<String, String> map;

    public int fresh;
}
class Message {
    public String msg;
    public String sig;
    public boolean ses;
}

public class EncryptionManager {
    private Context ctx;

    private String key = "";
    private KeyPair sessionKeyPair = null;
    private ECPublicKey peerKey = null;

    private SecretKey symKey = null;

    private ECPrivateKey longTermKeyPair = null;
    private ECPublicKey longTermPeerKey = null;
    private byte[] longTermSharedKey = null;

    private int messageCounter = 0;

    public ArrayList<String> displayedMessages = new ArrayList<>();

    public EncryptionManager(Context appCtx) {
        ctx = appCtx;
        importKeys();
    }

    public String processMessage(String text) {
        Gson gson = new Gson();
        Message msg = gson.fromJson(text, Message.class);
        Log.d("Received JSON", text);

        //If in handshake step
        //TODO: Improve the check for an handshake message
        if (messageCounter == 0 || !msg.ses) {
            String decodedMessageContent = new String(Base64.decode(msg.msg, Base64.DEFAULT), StandardCharsets.UTF_8);

            MessageContent content = extractMessageContent(msg);
            Log.d("Extracted Content Msg", content.msg);

            //Check freshness
            if (content.fresh != messageCounter) {
                return "ERROR: Freshness check failed!";
            }
            messageCounter = content.fresh + 1;

            if (content.hdr.equals("ERROR")) {
                return content.msg;
            }
            if (!content.hdr.equals("HANDSHAKE")) {
                return "ERROR: Incorrect expected header!";
            }

            if (!BuildConfig.hasOTP) {
                Handshake data = extractHandshakeData(content);
                //Check authenticity
                if (!checkAuthenticity(decodedMessageContent, msg, longTermPeerKey)) {
                    return "ERROR: Hash mismatch in the received message!";
                }


//            messageCounter = 1;

//            Map<String, String> yourMap = /*..;
                StringBuilder bob = new StringBuilder();
                for (Map.Entry<String,String> entry : data.map.entrySet()) {
                    bob.append(entry.getKey()).append("->").append(entry.getValue()).append("\n");
                }
                String mapStr = bob.toString();

                String result = handshakeSetup(data.key) + "Use the following mapping to input your password: " + mapStr;
                displayedMessages.add(result);
                return result;
            }
            else {

                String result = handshakeSetup(content.msg);
                displayedMessages.add(result);
                return result;
            }
        }

        //Decrypt
        String decryptedMsg = null;
        try {
            decryptedMsg = AESDecrypt(msg.msg, symKey);
        } catch (InvalidKeyException | BadPaddingException e) {
            String errorMsg = "ERROR - Failed to decrypt the message. " + e.getMessage();
            displayedMessages.add(errorMsg);
            return errorMsg;
        }

        //Extract
        MessageContent content = gson.fromJson(decryptedMsg, MessageContent.class);
        Log.d("Extracted Content Msg", decryptedMsg);

        //Check freshness
        if (content.fresh != messageCounter) {
            return "ERROR: Freshness check failed!";
        }
        messageCounter = content.fresh + 1;

        //Check authenticity
        if (!checkAuthenticity(decryptedMsg, msg, longTermPeerKey)) {
            return "ERROR: Hash mismatch in the received message!";
        }

        if (content.hdr.equals("OTP")) {
//            byte[] decodedKey = Base64.decode("k72vE3HJUNCbVqbcKo5el9QvhE/rEH86c/f6LmnBp3w=", Base64.DEFAULT);
//            SecretKey key = new SecretKeySpec(decodedKey, "AES");

            //Encryption test
//            String res = AESEncrypt("AAAAAA", key);
//            Log.d("TEST", res);


//            String challenge = AESDecrypt(content.msg, key);
            String toDisplay = "OTP Request:\nWrite the following in the interface:\n" + content.msg;
            displayedMessages.add(toDisplay);
            return toDisplay;
        }
        String mapStr = "";
        if (content.map != null) {
            StringBuilder bob = new StringBuilder();
            for (Map.Entry<String,String> entry : content.map.entrySet()) {
                bob.append(entry.getKey()).append("->").append(entry.getValue()).append("\n");
            }
            mapStr = bob.toString();
        }
        //Display message
        String finalStr = content.msg + "\n" + mapStr;
        displayedMessages.add(finalStr);
        return finalStr;
    }

    public KeyPair generateECKeyPair() {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");

            kpGen.initialize(new ECGenParameterSpec("prime256v1"));
            return kpGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    private MessageContent extractMessageContent(Message msg) {
        byte[] decodedMessageContent = Base64.decode(msg.msg, Base64.DEFAULT);
        String peak = new String(decodedMessageContent);
        Log.d("Extracted content", peak);

        Gson gson = new Gson();
        return gson.fromJson(new String(decodedMessageContent, StandardCharsets.UTF_8), MessageContent.class);
    }

    private Handshake extractHandshakeData(MessageContent msg) {
        byte[] decodedMessageContent = Base64.decode(msg.msg, Base64.DEFAULT);
        String peak = new String(decodedMessageContent);
        Gson gson = new Gson();
        return gson.fromJson(new String(decodedMessageContent, StandardCharsets.UTF_8), Handshake.class);
    }

    private void importKeys() {
        try {
            //Import system key
            byte[] encoded = importSingleKey("EC_GlassPrivKey.pem", "priv");
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encoded);
            longTermKeyPair = (ECPrivateKey) keyFactory.generatePrivate(privKeySpec);

            //Import TEE public key
            encoded = importSingleKey("EC_TEEPubKey.pem", "pub");
            keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded);
            longTermPeerKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

            longTermSharedKey = importSingleKey("sharedLTKeyB64.txt", "");
//            keyFactory = KeyFactory.getInstance("EC");
//            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded);
//            longTermPeerKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] importSingleKey(String path, String keyType) {
        try {
            FileInputStream fis = null;
            fis = ctx.openFileInput(path);

            InputStreamReader isr = new InputStreamReader(fis);
            BufferedReader bufferedReader = new BufferedReader(isr);
            StringBuilder sb = new StringBuilder();
            String fileContent;
            while ((fileContent = bufferedReader.readLine()) != null) {
                sb.append(fileContent);
            }
            String keyPEM = sb.toString();
            fis.close();

            if (keyType.equals("priv")) {
                 keyPEM = keyPEM
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END PRIVATE KEY-----", "");
            } else if(keyType.equals("pub")) {
                keyPEM = keyPEM
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END PUBLIC KEY-----", "");
            }
//            else {
//               return keyPEM.getBytes();
//            }

            if (keyPEM.isEmpty())
                return null;

            return Base64.decode(keyPEM, Base64.DEFAULT);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void clearSession() {
        sessionKeyPair = null;
        peerKey = null;
        symKey = null;
        messageCounter = 0;
    }

    public String generateECSessionKeyPair() {
        sessionKeyPair = generateECKeyPair();
        if (sessionKeyPair == null) {
            return "SETUP ERROR\nFailed to generate the session keys";
        }

        ECPublicKey ecPubKey = (ECPublicKey) sessionKeyPair.getPublic();
        ECPoint publicPoint = ecPubKey.getW();

        String compressedKeyPrefix = "";
        if(publicPoint.getAffineY().mod(new BigInteger("2")).equals(BigInteger.ZERO))
            compressedKeyPrefix = "02";
        else
            compressedKeyPrefix = "03";

        Log.d("pointX:", publicPoint.getAffineX().toString(16));
        Log.d("pointY:", publicPoint.getAffineY().toString(16));

        String outputHex = compressedKeyPrefix + publicPoint.getAffineX().toString(16);
        byte[] outputBytes = new BigInteger(outputHex, 16).toByteArray();
        String out = Base64.encodeToString(outputBytes, Base64.DEFAULT);

        Log.d("SecretKeyBase64:", key);
        Log.d("PubKeyInHex", outputHex);
        Log.d("PubKeyToSend", out);

        return "Connection Start\nWrite the following key in the keyboard:\n\n" + out;
    }

    private String handshakeSetup(String receivedPubKey) {
        Log.d("LTK:", new String(longTermSharedKey));
        Log.d("Received NONCE", receivedPubKey);
        byte[] decodedKey = Base64.decode(receivedPubKey, Base64.DEFAULT);
//
//        peerKey = ecPointToPublicKey(new String(decodedKey));
//        if (BuildConfig.hasOTP)
//            sessionKeyPair = generateECKeyPair();
//
//        if (peerKey == null || sessionKeyPair == null) {
//            return "Handshake ERROR\nFailed to either generate the session keys or retrieve the peer key";
//        }

        symKey = generateSharedSecret(decodedKey);
        if (symKey == null) {
            return "Handshake ERROR\nFailed to generate Shared Key";
        }
//        String key = Base64.encodeToString(symKey.getEncoded(), Base64.DEFAULT);
//
//        //No wrap simplifies the debug process (no need to hand write codes or copy-paste 76 characters at a time)
//        ECPublicKey ecPubKey = (ECPublicKey) sessionKeyPair.getPublic();
//        ECPoint publicPoint = ecPubKey.getW();
//
//        String compressedKeyPrefix = "";
//        if(publicPoint.getAffineY().mod(new BigInteger("2")).equals(BigInteger.ZERO))
//            compressedKeyPrefix = "02";
//        else
//            compressedKeyPrefix = "03";
//
//        Log.d("pointX:", publicPoint.getAffineX().toString(16));
//        Log.d("pointY:", publicPoint.getAffineY().toString(16));
//
//        String outputHex = compressedKeyPrefix + publicPoint.getAffineX().toString(16);
//        byte[] outputBytes = new BigInteger(outputHex, 16).toByteArray();
//        String out = Base64.encodeToString(outputBytes, Base64.DEFAULT);
//
//        Log.d("SecretKeyBase64:", key);
//        Log.d("PubKeyInHex", outputHex);
//        Log.d("PubKeyToSend", out);
        Log.d("Obtained Key", Base64.encodeToString(symKey.getEncoded(), Base64.DEFAULT));
        return "Handshake OK\nPress \"Login\" to continue.";

//        if(BuildConfig.hasOTP)
//            return "Handshake OK\nWrite the following key in the keyboard:\n\n" + out;
//        else
    }

    private boolean checkAuthenticity(String decryptedMsg, Message msg, ECPublicKey key) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(key);
            sig.initVerify(key);
            sig.update(decryptedMsg.getBytes());
            return sig.verify(Base64.decode(msg.sig, Base64.DEFAULT));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
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

    private SecretKey generateSharedSecret(byte[] nonce) {
        try {
            byte[] secretKey = new byte[32];

            SHA256Digest sha256 = new SHA256Digest();
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(sha256);

            hkdf.init(new HKDFParameters(longTermSharedKey, nonce, null));

            hkdf.generateBytes(secretKey, 0, 32);
//            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
//            keyAgreement.init(privateKey);
//            keyAgreement.doPhase(publicKey, true);

//            SecretKey key = keyAgreement.generateSecret("AES");
            SecretKey key = new SecretKeySpec(secretKey, 0, secretKey.length, "AES");
            return key;
        } catch (Exception e) {
            return null;
        }
    }

    private String AESDecrypt(String cipherText, SecretKey decryptionKey) throws InvalidKeyException, BadPaddingException {
        try {
            byte[] cipherBytes = Base64.decode(cipherText, Base64.DEFAULT);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            AlgorithmParameterSpec gcmParameterSpec = new GCMParameterSpec(128, cipherBytes, 0, 16);

            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmParameterSpec);

            byte[] plainText = cipher.doFinal(cipherBytes, 16, cipherBytes.length - 16);
            return new String(plainText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException e) {
            //Likely programmer error
            throw new RuntimeException(e);
        }
    }

    private String AESEncrypt(String plainText, SecretKey key) {
        byte[] iv = "0123456789012345".getBytes(StandardCharsets.UTF_8);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            AlgorithmParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
//            byte[] cipherBytes = Base64.decode(plainText, Base64.DEFAULT);
            byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
            return Base64.encodeToString(cipherText, Base64.DEFAULT);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
