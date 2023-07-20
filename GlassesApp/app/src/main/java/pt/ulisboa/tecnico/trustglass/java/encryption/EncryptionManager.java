package pt.ulisboa.tecnico.trustglass.java.encryption;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class MessageContent {
    public String hdr;
    public String msg;

    public Map<String, String> map;

    public int fresh;
}
class Message {
    public String msg;
    public String sig;
    public boolean enc;
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
        if (messageCounter == 0 && !msg.enc) {
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

            String result = handshakeSetup(content.msg);
            displayedMessages.add(result);
            return result;
        }
        //Likely an error
        else if (!msg.enc) {
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

            String result = handshakeSetup(content.msg);
            displayedMessages.add(result);
            return result;
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

        String mapStr = "";
        if (content.map != null) {
            StringBuilder bob = new StringBuilder();
            bob.append("\nYou can scroll this mapping to view all the characters.\nFROM ---> TO\n");
            for (Map.Entry<String,String> entry : content.map.entrySet()) {
                bob.append("\t\t\t\t\t "+entry.getKey()).append(" ---> ").append(entry.getValue()).append("\n");
            }
            mapStr = bob.toString();
        }
        //Display message
        String finalStr = content.msg + "\n" + mapStr;
        displayedMessages.add(finalStr);
        return finalStr;
    }

//    public KeyPair generateECKeyPair() {
//        try {
//            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC");
//
//            kpGen.initialize(new ECGenParameterSpec("prime256v1"));
//            return kpGen.generateKeyPair();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        } catch (InvalidAlgorithmParameterException e) {
//            throw new RuntimeException(e);
//        }
//    }

    private MessageContent extractMessageContent(Message msg) {
        byte[] decodedMessageContent = Base64.decode(msg.msg, Base64.DEFAULT);
        String peak = new String(decodedMessageContent);
        Log.d("Extracted content", peak);

        Gson gson = new Gson();
        return gson.fromJson(new String(decodedMessageContent, StandardCharsets.UTF_8), MessageContent.class);
    }


    private void importKeys() {
        try {
            // For demonstration purposes, the long-term shared key is hardcoded
            // In a real implementation, the key would be established in a prior step via ECDH, and stored locally in an encrypted keystore
            String b64LTK = "W/EC20gaJJTuMGzqwIezjUeSdJhHh0VpiTWrZiHOUO3h4faUyy9ALcImwphBIFoawXDVfj2jti28" +
                    "yjYAQJJcHMZwsRkx37iwO6sWL+6xPcF+bUuG3G174Itc2wV+7poGNH2D9q2umCLJC/l+6UdyTvjp" +
                    "CBNd6EEkMk0SeJzp0MGNVn7zYcs7C6H7FhqwL9lP94Bl6nw7r8kHx9KPVQh+krlGzHmoc5Z+wIx4" +
                    "qkQ61smpc4jsOcfWSzcIWXEbTM8LK8LZYF4g+jbKvZ/bbDhCX6U381eZhZ0y8yanC5B98Lw9QtRM" +
                    "tV9Ge05XcHSA8jpMtngdo/+BIlRADwNuAWPGLg==";

            longTermSharedKey = Base64.decode(b64LTK, Base64.DEFAULT);

        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    private String handshakeSetup(String receivedPubKey) {
        Log.d("LTK:", new String(longTermSharedKey));
        Log.d("Received NONCE", receivedPubKey);
        byte[] decodedKey = Base64.decode(receivedPubKey, Base64.DEFAULT);

        symKey = generateSharedSecret(decodedKey);
        if (symKey == null) {
            return "Handshake ERROR\nFailed to generate Shared Key";
        }

        // Prints for debug purposes
//        Log.d("SecretKeyBase64:", key);
//        Log.d("PubKeyInHex", outputHex);
//        Log.d("PubKeyToSend", out);

        Log.d("Obtained Key", Base64.encodeToString(symKey.getEncoded(), Base64.DEFAULT));
        return "Handshake OK\nPress \"Login\" to continue.";
    }

    private SecretKey generateSharedSecret(byte[] nonce) {
        try {
            byte[] secretKey = new byte[32];

            SHA256Digest sha256 = new SHA256Digest();
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(sha256);

            hkdf.init(new HKDFParameters(longTermSharedKey, nonce, null));

            hkdf.generateBytes(secretKey, 0, 32);

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
}
