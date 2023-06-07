package com.tw.jwt.infrastructure.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

@Slf4j
public class JwtRsaUtils {

    /**
     * 提供公钥字符串，返回RSAKey
     *
     * @param keyId
     * @param publicKey
     * @return
     */
    public static RSAKey getRsaKey(String keyId, String publicKey) throws InvalidKeySpecException {
        return getRsaKey(keyId, RsaUtils.getPublicKey(publicKey));
    }

    /**
     * 提供公钥和私钥字符串，返回RSAKey
     *
     * @param keyId
     * @param publicKey
     * @param privateKey
     * @return
     */
    public static RSAKey getRsaKey(String keyId, String publicKey, String privateKey) throws InvalidKeySpecException {
        return getRsaKey(keyId, RsaUtils.getPublicKey(publicKey), RsaUtils.getPrivateKey(privateKey));
    }

    /**
     * 提供公钥，返回RSAKey
     *
     * @param keyId
     * @param publicKey
     * @return
     */
    public static RSAKey getRsaKey(String keyId, PublicKey publicKey) {
        return new RSAKey.Builder((RSAPublicKey) publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(keyId)
                .build();
    }

    /**
     * 提供公钥和私钥，返回RSAKey
     *
     * @param keyId
     * @param publicKey
     * @param privateKey
     * @return
     */
    public static RSAKey getRsaKey(String keyId, PublicKey publicKey, PrivateKey privateKey) {
        return new RSAKey.Builder((RSAPublicKey) publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(keyId)
                .build();
    }

    /**
     * 根据RSAKey签名
     *
     * @param rsaKey
     * @return
     * @throws JOSEException
     */
    public static String sign(RSAKey rsaKey) throws JOSEException {
        return sign(rsaKey, new JWTClaimsSet.Builder().build());
    }

    /**
     * 根据RSAKey签名
     *
     * @param rsaKey
     * @param aud
     * @return
     * @throws JOSEException
     */
    public static String sign(RSAKey rsaKey, String... aud) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(Arrays.asList(aud))
                .build();
        return sign(rsaKey, claimsSet);
    }

    /**
     * 根据RSAKey签名，可设置过期时间
     *
     * @param rsaKey
     * @param expire 过期时间，单位毫秒
     * @param aud
     * @return
     * @throws JOSEException
     */
    public static String sign(RSAKey rsaKey, long expire, String... aud) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(Arrays.asList(aud))
                .expirationTime(new Date(System.currentTimeMillis() + expire))
                .build();
        return sign(rsaKey, claimsSet);
    }

    /**
     * 根据RSAKey签名，可设置过期时间
     *
     * @param rsaKey
     * @param issuer  iss
     * @param subject sub
     * @param expire  过期时间，单位毫秒
     * @param aud
     * @return
     * @throws JOSEException
     */
    public static String sign(RSAKey rsaKey, String issuer, String subject, long expire, String... aud) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(Arrays.asList(aud))
                .expirationTime(new Date(System.currentTimeMillis() + expire))
                .build();
        return sign(rsaKey, claimsSet);
    }

    /**
     * 签名
     *
     * @param rsaKey
     * @param claimsSet
     * @return
     * @throws JOSEException
     */
    public static String sign(RSAKey rsaKey, JWTClaimsSet claimsSet) throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claimsSet);
        signedJWT.sign(new RSASSASigner(rsaKey));
        return signedJWT.serialize();
    }

    /**
     * 私钥加密
     *
     * @param privateKey
     * @param claimsSet
     * @return
     * @throws JOSEException
     */
    public static String signByPrivateKey(RSAPrivateKey privateKey, JWTClaimsSet claimsSet) throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claimsSet);
        signedJWT.sign(new RSASSASigner(privateKey));
        return signedJWT.serialize();
    }

    public static boolean verifyByPublicKey(RSAPublicKey publicKey, String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            if (signedJWT.getJWTClaimsSet().getExpirationTime() != null) {
                if (!new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                    return false;
                }
            }

            RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
            return signedJWT.verify(verifier);
        } catch (ParseException e) {
            log.debug("解析JWT失败", e);
            return false;
        } catch (JOSEException e) {
            log.debug("解析JWT时密钥错误", e);
            return false;
        }
    }

    /**
     * 验证签名
     *
     * @param rsaKey
     * @param token
     * @return
     */
    public static boolean verify(RSAKey rsaKey, String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            if (signedJWT.getJWTClaimsSet().getExpirationTime() != null) {
                if (!new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                    return false;
                }
            }

            RSASSAVerifier verifier = new RSASSAVerifier(rsaKey);
            return signedJWT.verify(verifier);
        } catch (ParseException e) {
            log.debug("解析JWT失败", e);
            return false;
        } catch (JOSEException e) {
            log.debug("解析JWT时密钥错误", e);
            return false;
        }
    }

    /**
     * 验证签名并返回JWT对象
     *
     * @param rsaKey
     * @param token
     * @return 如果返回值为null就表示验证失败
     */
    public static SignedJWT verifyWithData(RSAKey rsaKey, String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            if (signedJWT.getJWTClaimsSet().getExpirationTime() != null) {
                if (!new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                    return null;
                }
            }

            RSASSAVerifier verifier = new RSASSAVerifier(rsaKey);
            if (signedJWT.verify(verifier)) {
                return signedJWT;
            } else {
                return null;
            }
        } catch (ParseException e) {
            log.debug("解析JWT失败", e);
            return null;
        } catch (JOSEException e) {
            log.debug("解析JWT时密钥错误", e);
            return null;
        }
    }

    public static void main(String[] args) throws InvalidKeySpecException, JOSEException, ParseException {
        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5Kp69FYm84eepGVOAYrN\n" +
                "iaqWDeHvNTi6VGxx2OmZYV52wv08C29TYDBuGsCPrFOraEPF4PSLmxjewjWjkRA0\n" +
                "XZYsYMb6isk/sahhntLON2yxfVbKVEJCyiAcFQvZZ22pnKT6pStUFc3PYnaPWGFe\n" +
                "lzkEbpmyRax8tVCHYdU8L9t2QmH9fPOu5LEXAZxDqVDBCzR08MUR1h/VbQCbCs/d\n" +
                "z5X+py3/RQ1OQ20Ih2cJZAcXTy+E59uAvqwpq83aOj15rZ1PGWwvrpiaJImh4yMT\n" +
                "EC9SdHk+LggQG6gp3A5nLdVY76jUgsvE89xcrXtJy4h1Ytlux74J0E/s5LeOxNex\n" +
                "jwIDAQAB\n" +
                "-----END PUBLIC KEY-----";
        String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDkqnr0Vibzh56k\n" +
                "ZU4Bis2JqpYN4e81OLpUbHHY6ZlhXnbC/TwLb1NgMG4awI+sU6toQ8Xg9IubGN7C\n" +
                "NaOREDRdlixgxvqKyT+xqGGe0s43bLF9VspUQkLKIBwVC9lnbamcpPqlK1QVzc9i\n" +
                "do9YYV6XOQRumbJFrHy1UIdh1Twv23ZCYf18867ksRcBnEOpUMELNHTwxRHWH9Vt\n" +
                "AJsKz93Plf6nLf9FDU5DbQiHZwlkBxdPL4Tn24C+rCmrzdo6PXmtnU8ZbC+umJok\n" +
                "iaHjIxMQL1J0eT4uCBAbqCncDmct1VjvqNSCy8Tz3Fyte0nLiHVi2W7HvgnQT+zk\n" +
                "t47E17GPAgMBAAECggEBAOEijI42qIELXQGFEGlqTPWm87hVY5wl7yah4vFrBW2d\n" +
                "gRZ4F382q4NAC5fhUVOcyV2NpKzYeP9KXEAgaZuwta4S5jyejBzLCiATpZGnAgwF\n" +
                "wzahlfGhj3rMZHnAQduYV+93a6PlZhNVoELUckvVCjmflKKERsZcjihCUhjbxjdi\n" +
                "YoagrluFz6LvtrlCBCi9pLXZ80/WSUbswJ4DUyszU3LPDQ+mGihIygumpjAxIbdV\n" +
                "62rhyCylPICBKTwmtTmBWbSi6HyaF8XEsT7WqOGVj4Ka1Kw11FqFFjlFqr8j8//U\n" +
                "3LJY5BYF94kPGYdjRgY1uCmdd7yOBjoe30fkrLHiEzkCgYEA+Vi1q28dcxZqMYsi\n" +
                "FMq0pulW8Uap+9rMGY8J9+jMDaesAgs+GsmeKfboc4LJHF1AgvUGsrNtl5z1qekY\n" +
                "1c+c8Hgd0v0Jibri9At3MxbUJbMerKMiA19gAqBtPDnx1f4TwQZu/BqEPp9/0nKI\n" +
                "IjPtNkUxqAk5SkSjO1cNcm+rs/0CgYEA6sSAUEacRsLLMkjkav9PcO4nozr6n6rd\n" +
                "8yuaT1SI1NM4Adv4nR43DXXiQBhluSl8BCHNDLkadWn6OXvbRRvmC4ETV+nsyiC2\n" +
                "6xkJY1vjhBQbLR6i/GvuutuSg4Ix0fraz/pwO8O/tGM6nq89nDi3xGCZhhs6HQOo\n" +
                "b1Vh4oJBQ3sCgYEA7PhNz1uOlW3cBrG/9hqfjXF9W1hY/C54gmHai20HYILViiu9\n" +
                "HiA23JL3X7AQCZDmWo8bioHTyZ82KgCJxcnF0ROW5InuoqKmRmEPK9KqVBnjMRbo\n" +
                "oGPoDxcAOZioKUOK6ot+tsFMpWdYR1zp2/eVnVotUxFRDTAmIaMd+IAAotECgYEA\n" +
                "iPoJ28y3FdpF8JrzGzLHyR5LZkPdQxfQ1DbWm/64r2Rlwz/zOMkOWf4z+i3B/F0m\n" +
                "DMsj9o5xz5v78VpAv3vdp0yyWpMUI4Me9uDux1gv0Tph+NttQVZAPioqvCxUoS16\n" +
                "SerXXSeDTN6wrzGUAvhc0GmEaeis6Yze08a/jAdvyM0CgYEApYN9OITROuaHZJWY\n" +
                "vjBhDlmGnVnKdskGQlI4OAg0qFRvCB6HGLz690OObSQbCsftD06ecZitrTi3mXH9\n" +
                "cRQu9ibiGls4Xk2L6Ci5SuFFj/6oJ0PvmY1XJlm9vPZ1XAZVdF7sKXO04VHkLvBB\n" +
                "OP7ymZDum/xkGekHtaAdG4HKrVU=\n" +
                "-----END PRIVATE KEY-----\n";

        RSAPublicKey rsaPublicKey = (RSAPublicKey) RsaUtils.getPublicKey(publicKey);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) RsaUtils.getPrivateKey( privateKey);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("issuer")
                .subject("subject")
                .audience(Arrays.asList("1", "2", "3"))
                .expirationTime(new Date(System.currentTimeMillis() + 10000L))
                .build();
        String token = signByPrivateKey(rsaPrivateKey, claimsSet);
        System.out.println(verifyByPublicKey(rsaPublicKey, token));

//        // keyId 是随便填的字符串
//        RSAKey rsaKey = JwtRsaUtils.getRsaKey("keyId", publicKey, privateKey);
//        String token = JwtRsaUtils.sign(rsaKey, "issuer", "subject", 100000L);
//
//        // 直接解析不验证，这一步是不需要密钥的，因为是明文的
//        SignedJWT jwt = SignedJWT.parse(token);
//        List<String> audience = jwt.getJWTClaimsSet().getAudience();
//
//        // 验证
//        if (JwtRsaUtils.verify(rsaKey, token)) {
//            // 验证通过
//            System.out.println(token);
//        }
//
//        // 验证并返回payload
//        jwt = JwtRsaUtils.verifyWithData(rsaKey, token);
//        if (jwt != null) {
//            // 验证通过
//            System.out.println("验证通过");
//            audience = jwt.getJWTClaimsSet().getAudience();
//            System.out.println(audience);
//        }

    }
}
