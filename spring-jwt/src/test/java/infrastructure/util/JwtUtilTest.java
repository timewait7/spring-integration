package infrastructure.util;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.tw.jwt.infrastructure.util.JwtUtil;
import com.tw.jwt.infrastructure.util.RSAUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Slf4j
public class JwtUtilTest {

    @Test
    public void test_sign() throws NoSuchAlgorithmException, JOSEException {
        PrivateKey privateKey = RSAUtil.getPrivateKey();

        // header
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();

        // payload
        long current = System.currentTimeMillis();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("team_id", 1)
                .claim("username", "zhang3")
                .claim("platform", "mac")
                .claim("us", "user_agent")
                .issueTime(new Date(current))
                .expirationTime(new Date(current + 24 * 60 * 60 * 1000))
                .build();

        // sign
        String token = JwtUtil.sign((RSAPrivateKey) privateKey, header, claimsSet);

        assertNotNull(token);

        System.out.println("Token: " + token);
    }

    @Test
    public void test_verify() throws NoSuchAlgorithmException, JOSEException {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // header
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();

        // payload
        long current = System.currentTimeMillis();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("team_id", 1)
                .claim("username", "zhang3")
                .claim("platform", "mac")
                .claim("us", "user_agent")
                .issueTime(new Date(current))
                .expirationTime(new Date(current + 24 * 60 * 60 * 1000))
                .build();

        // sign
        String token = JwtUtil.sign((RSAPrivateKey) privateKey, header, claimsSet);

        boolean verify = JwtUtil.verify((RSAPublicKey) publicKey, token);
        assertTrue(verify);
    }
}
