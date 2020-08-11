/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.cryptochallenge;

import com.nimbusds.jwt.Base64URL;
import com.nimbusds.jwt.ClaimsSet;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.Header;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWEHeader;
import com.nimbusds.jwt.ReadOnlyJWEHeader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import net.minidev.json.JSONObject;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class JWTTest {

    public void testConstructor() throws Exception {

        JWEHeader h = new JWEHeader(JWA.RSA1_5);
        h.setType(Header.Type.JWT);
        h.setEncryptionMethod(JWA.A128GCM);
        final byte[] ivBytes = Hex.decode("cafebabefacedbaddecaf888");
        h.setInitializationVector(Base64URL.encode(ivBytes));

        JSONObject claims = new JSONObject();
        claims.put("iss", "http://nimbusds.com");
        claims.put("exp", 123);
        claims.put("act", true);

//                KeyGenerator keygen;
//                keygen = KeyGenerator.getInstance("RSA");
//                keygen.init(1024);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        EncryptedJWT jwt = new EncryptedJWT(h, new ClaimsSet(claims));
        jwt.rsaEncrypt(publicKey);
        System.out.println(jwt.getState());
        System.out.println(jwt.serialize());

        jwt.rsaDecrypt(privateKey);
        System.out.println(jwt.getState());
        System.out.println(jwt.serialize());
        System.out.println(jwt.getClaimsSet());

        System.out.println(jwt.getHeader());
        System.out.println(jwt.getEncryptedKey());
        System.out.println(jwt.getCipherText());
        System.out.println(jwt.getIntegrityValue());

        ReadOnlyJWEHeader hOut = jwt.getHeader();
    }
}
