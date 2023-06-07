package com.tw.jwt.infrastructure.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyGeneratorUtil {

    //数字签名
    public static final String KEY_ALGORITHM = "RSA";

    //RSA密钥长度
    public static final int KEY_SIZE = 1024;

    //唯一的密钥实例
    private static volatile RSA256Key rsa256Key;

    /**
     * 生成 公钥/私钥
     *
     *  由双重校验锁保证创建唯一的密钥实例，因此创建完成后仅有唯一实例。
     *  当被JVM回收后，才会创建新的实例
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static RSA256Key generateRSA256Key() throws NoSuchAlgorithmException {

        //第一次校验：单例模式只需要创建一次实例，若存在实例，不需要继续竞争锁，
        if (rsa256Key == null) {
            //RSA256Key单例的双重校验锁
            synchronized(RSA256Key.class) {
                //第二次校验：防止锁竞争中自旋的线程，拿到系统资源时，重复创建实例
                if (rsa256Key == null) {
                    //密钥生成所需的随机数源
                    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
                    keyPairGen.initialize(KEY_SIZE);
                    //通过KeyPairGenerator生成密匙对KeyPair
                    KeyPair keyPair = keyPairGen.generateKeyPair();
                    //获取公钥和私钥
                    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
                    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
                    rsa256Key = new RSA256Key();
                    rsa256Key.setPublicKey(publicKey);
                    rsa256Key.setPrivateKey(privateKey);
                }

            }
        }
        return rsa256Key;
    }

}
