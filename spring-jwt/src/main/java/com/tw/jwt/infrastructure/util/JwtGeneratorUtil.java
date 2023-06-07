package com.tw.jwt.infrastructure.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import static com.tw.jwt.infrastructure.util.KeyGeneratorUtil.KEY_ALGORITHM;
import static com.tw.jwt.infrastructure.util.KeyGeneratorUtil.KEY_SIZE;

@Slf4j
public class JwtGeneratorUtil {
    /**
     * 签发Token
     * <p>
     * withIssuer()给PAYLOAD添加一跳数据 => token发布者
     * withClaim()给PAYLOAD添加一跳数据 => 自定义声明 （key，value）
     * withIssuedAt() 给PAYLOAD添加一条数据 => 生成时间
     * withExpiresAt()给PAYLOAD添加一条数据 => 保质期
     *
     * @param data
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String creatTokenByRS256(Object data) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(KEY_SIZE);
        //通过KeyPairGenerator生成密匙对KeyPair
        KeyPair keyPair = keyPairGen.generateKeyPair();
        //获取公钥和私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();


        //初始化 公钥/私钥
        RSA256Key rsa256Key = KeyGeneratorUtil.generateRSA256Key();

        //加密时，使用私钥生成RS算法对象
        Algorithm algorithm = Algorithm.RSA256(rsa256Key.getPrivateKey());

        System.out.println(rsa256Key.getPrivateKey());

        return JWT.create()
                //签发人
                .withIssuer("ISSUER")
                //接收者
                //签发时间
                .withIssuedAt(new Date(System.currentTimeMillis()))
                //过期时间
                .withExpiresAt(new Date(System.currentTimeMillis() + 10000L))
                //相关信息
                .withClaim("data", "data")
                //签入
                .sign(algorithm);
    }

    public static boolean verifierToken(String token) throws NoSuchAlgorithmException {

        //获取公钥/私钥
        RSA256Key rsa256Key = KeyGeneratorUtil.generateRSA256Key();



        //根据密钥对生成RS256算法对象
        Algorithm algorithm = Algorithm.RSA256(rsa256Key.getPublicKey());

        System.out.println(rsa256Key.getPublicKey());

        //解密时，使用gong钥生成算法对象
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("ISSUER")
                .build();

        try {
            //验证Token，verifier自动验证
            DecodedJWT jwt = verifier.verify(token);
            return true;
        } catch (JWTVerificationException e) {
            log.error("Token无法通过验证! " + e.getMessage());
            return false;
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String token = creatTokenByRS256(null);
        System.out.println(token);
        System.out.println(verifierToken(token));
    }
}
