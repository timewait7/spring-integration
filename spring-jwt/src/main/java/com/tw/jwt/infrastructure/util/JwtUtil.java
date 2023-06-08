package com.tw.jwt.infrastructure.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

@Slf4j
public class JwtUtil {

    public static String sign(RSAPrivateKey privateKey, JWTClaimsSet claimsSet) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        return sign(privateKey, header, claimsSet);
    }

    public static String sign(RSAPrivateKey privateKey, JWSHeader header, JWTClaimsSet claimsSet) throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new RSASSASigner(privateKey));
        return signedJWT.serialize();
    }

    public static boolean verify(RSAPublicKey publicKey, String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            if (signedJWT.getJWTClaimsSet().getExpirationTime() != null) {
                if (!new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime())) {
                    log.info("Token超时");
                    return false;
                }
            }

            RSASSAVerifier verifier = new RSASSAVerifier(publicKey);
            return signedJWT.verify(verifier);
        } catch (ParseException e) {
            log.info("JWT解析失败", e);
            return false;
        } catch (JOSEException e) {
            log.info("JWT解析公钥错误", e);
            return false;
        }
    }
}
