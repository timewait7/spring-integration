package com.tw.jwt.infrastructure.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
public class RsaUtils {

    private static final int KEY_SIZE = 2048;

    /**
     * 生成密钥对
     *
     * @return
     */
    public static KeyPair create() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * 从字符串得到公钥
     *
     * @param key
     * @return
     */
    public static PublicKey getPublicKey(String key) throws InvalidKeySpecException {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(initKey(key));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            log.debug("公钥错误", e);
            throw e;
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * 从字符串得到私钥
     *
     * @param key
     * @return
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKey(String key) throws InvalidKeySpecException {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(initKey(key));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            log.debug("私钥错误", e);
            throw e;
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * 公钥转字符串
     *
     * @param key
     * @return
     */
    public static String toPublicKeyString(PublicKey key) {
        return Base64.encodeBase64String(key.getEncoded());
    }

    /**
     * 私钥转字符串
     *
     * @param key
     * @return
     */
    public static String toPrivateKeyString(PrivateKey key) {
        return Base64.encodeBase64String(key.getEncoded());
    }

    /**
     * 使用私钥加密
     *
     * @param string
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptByPrivateKey(String string, String key) throws Exception {
        PrivateKey privateKey = getPrivateKey(key);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        // 由于长度限制，需要分开加密
        byte[] data = string.getBytes();
        int blockLength = KEY_SIZE / 8 - 11;
        int offset = 0;
        int i = 0;
        int length = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] cache;
        while (length - offset > 0) {
            if (length - offset > blockLength) {
                cache = cipher.doFinal(data, offset, blockLength);
            } else {
                cache = cipher.doFinal(data, offset, length - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * blockLength;
        }

        byte[] bytes = out.toByteArray();
        out.close();

        return Base64.encodeBase64String(bytes);
    }

    /**
     * 使用公钥加密
     *
     * @param string
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(String string, String key) throws Exception {
        PublicKey publicKey = getPublicKey(key);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // 由于长度限制，需要分开加密
        byte[] data = string.getBytes();
        int blockLength = KEY_SIZE / 8 - 11;
        int offset = 0;
        int i = 0;
        int length = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] cache;
        while (length - offset > 0) {
            if (length - offset > blockLength) {
                cache = cipher.doFinal(data, offset, blockLength);
            } else {
                cache = cipher.doFinal(data, offset, length - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * blockLength;
        }

        byte[] bytes = out.toByteArray();
        out.close();

        return Base64.encodeBase64String(bytes);
    }

    /**
     * 使用私钥解密
     *
     * @param string
     * @param key
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKey(String string, String key) throws Exception {
        PrivateKey privateKey = getPrivateKey(key);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // 由于长度限制，需要分开加密
        byte[] data = Base64.decodeBase64(string);
        int length = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        int blockLength = KEY_SIZE / 8;
        while (length - offset > 0) {
            if (length - offset > blockLength) {
                cache = cipher.doFinal(data, offset, blockLength);
            } else {
                cache = cipher.doFinal(data, offset, length - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * blockLength;
        }

        byte[] bytes = out.toByteArray();
        out.close();

        return new String(bytes, "utf-8");
    }

    /**
     * 使用公钥解密
     *
     * @param string
     * @param key
     * @return
     * @throws Exception
     */
    public static String decryptByPublicKey(String string, String key) throws Exception {
        PublicKey publicKey = getPublicKey(key);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        // 由于长度限制，需要分开加密
        byte[] data = Base64.decodeBase64(string);
        int length = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        int blockLength = KEY_SIZE / 8;
        while (length - offset > 0) {
            if (length - offset > blockLength) {
                cache = cipher.doFinal(data, offset, blockLength);
            } else {
                cache = cipher.doFinal(data, offset, length - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * blockLength;
        }

        byte[] bytes = out.toByteArray();
        out.close();

        return new String(bytes, "utf-8");
    }

    /**
     * 去除密钥中的开头和结尾以及换行符，并转成byte[]
     *
     * @param key
     * @return
     */
    private static byte[] initKey(String key) {
        if (key.contains("-----BEGIN PRIVATE KEY-----")) {
            key = key.substring(key.indexOf("-----BEGIN PRIVATE KEY-----") + 27);
        }
        if (key.contains("-----BEGIN PUBLIC KEY-----")) {
            key = key.substring(key.indexOf("-----BEGIN PUBLIC KEY-----") + 26);
        }
        if (key.contains("-----END PRIVATE KEY-----")) {
            key = key.substring(0, key.indexOf("-----END PRIVATE KEY-----"));
        }
        if (key.contains("-----END PUBLIC KEY-----")) {
            key = key.substring(0, key.indexOf("-----END PUBLIC KEY-----"));
        }
        key = key.replaceAll("\r\n", "");
        key = key.replaceAll("\n", "");
        return Base64.decodeBase64(key);
    }
}
