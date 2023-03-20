package pt.ulisboa.tecnico.trustglass.java.encryption;

import android.content.Context;
import android.os.Environment;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

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
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

class Message {
    public String header;
    public String msg;
    public String sig;
    public String fresh;
}

public class EncryptionManager {
    private Context ctx;

    private String key = "";
    private KeyPair sessionKeyPair = null;
    private PublicKey peerKey = null;

    private SecretKey symKey = null;

    private RSAPrivateKey longTermKeyPair = null;
    private RSAPublicKey longTermPeerKey = null;

    public EncryptionManager(Context appCtx) {
        ctx = appCtx;
        importKeys();
    }

    public String processMessage(String text) {
        Gson gson = new Gson();
        Message msg = gson.fromJson(text, Message.class);
        Log.d("Received JSON", text);
        //If in handshake step
        if (msg.header.equals("HANDSHAKE")) {
            return handshakeSetup(msg);
        }

        //Decrypt
        String decryptedMsg = AESDecrypt(msg.msg);

        //Check authenticity
        if (!checkAuthenticity(decryptedMsg, msg)) {
            return "ERROR: Hash mismatch in the received message!";
        }
        //Check freshness

        //Display message
        return decryptedMsg;
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

    private void importKeys() {
        try {
            //Import system key
            byte[] encoded = importSingleKey("GlassKeyPair.pem", true);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encoded);
            longTermKeyPair = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);

            //Import TEE public key
            encoded = importSingleKey("TEEPubKey.pem", false);
            keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded);
            longTermPeerKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] importSingleKey(String path, boolean isPrivate) {
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
            if (isPrivate) {
                 keyPEM = keyPEM
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END PRIVATE KEY-----", "");
            } else {
                keyPEM = keyPEM
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END PUBLIC KEY-----", "");
            }

            fis.close();

            if (keyPEM.isEmpty())
                return null;

            return Base64.decode(keyPEM, Base64.DEFAULT);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String handshakeSetup(Message msg) {
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

        return "Handshake OK\nWrite the following key in the keyboard:\n\n" + pubKeyToSend;
    }

    private boolean checkAuthenticity(String decryptedMsg, Message msg) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(longTermPeerKey);
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

    private String AESDecrypt(String cipherText) {
        // A 128 bit IV
        // TODO: Remove this, it should not be hardcoded
        byte[] iv = "0123456789012345".getBytes(StandardCharsets.UTF_8);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, symKey, ivSpec);
            byte[] plainText = cipher.doFinal(Base64.decode(cipherText, Base64.DEFAULT));
            return new String(plainText);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
