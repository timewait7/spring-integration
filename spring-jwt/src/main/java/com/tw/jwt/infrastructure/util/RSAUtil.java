package com.tw.jwt.infrastructure.util;

import org.apache.commons.codec.binary.Base64;


import java.security.*;

public class RSAUtil {

    private static final String ALG = "RSA";

    private static final int KEY_SIZE = 2048;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALG);
        keyPairGenerator.initialize(KEY_SIZE);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        System.out.println("私钥: " + new String(Base64.encodeBase64(privateKey.getEncoded())));
        System.out.println("公钥: " + new String(Base64.encodeBase64(publicKey.getEncoded())));

        return keyPair;
    }

    public static PublicKey getPublicKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        return keyPair.getPublic();
    }

    public static String getPublicKeyStr() throws NoSuchAlgorithmException {
        PublicKey publicKey = getPublicKey();
        return new String(Base64.encodeBase64(publicKey.getEncoded()));
    }

    public static PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        return keyPair.getPrivate();
    }

    public static String getPrivateKeyStr() throws NoSuchAlgorithmException {
        PrivateKey privateKey = getPrivateKey();
        return new String(Base64.encodeBase64(privateKey.getEncoded()));
    }
}
