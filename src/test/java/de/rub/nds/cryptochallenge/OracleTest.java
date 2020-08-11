package de.rub.nds.cryptochallenge;

import com.nimbusds.jwt.Base64URL;
import com.nimbusds.jwt.ClaimsSet;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.Header;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWEHeader;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import net.minidev.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Unit test for simple App.
 */
public class OracleTest
        extends TestCase {

    private static String logfile = "logging.properties";
    private static String keystore = "keystore512.jks";
    private static String alias = "rub";
    private static char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    static Logger logger = Logger.getRootLogger();
    private final static String test = "eyJhbGciOiJSU0ExXzUiLCJpdiI6Inl2NjZ2dnJPMjYzZXl2aUlFeFFWRmciLCJ0eXAiOiJKV1QiLCJlbmMiOiJBMTI4Q0JDIn0.O29uvG-WppDp3GiOV4p3DX9ZcHQTGFqJOZAyF9M-3ksyxtEeoP0o8CkqmWzKZRmXuGWQEKWwK7FhzRYEzavyPw.eH_40Bgm6MeODZ-yw5yAdOyquyrAM-cdBlRad7imqnTTqY9MOKJlXuVZi7IzkwN3l1JR_TzffkDtlqN4mYvRmW9kILpf3C492OT7aeYBpNQ.";
    private final static String url = "http://localhost:50080/service";
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public OracleTest(String testName) throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {
        super(testName);

        PropertyConfigurator.configure(logfile);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(keystore);
            keyStore.load(fis, password);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        publicKey = (RSAPublicKey) keyStore.getCertificate(alias).getPublicKey();
        privateKey = (RSAPrivateKey) keyStore.getKey(alias, password);
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(OracleTest.class);
    }

    public void testEncryptJWTClaims() throws Exception {
        JWEHeader h = new JWEHeader(JWA.RSA1_5);
        h.setType(Header.Type.JWT);
        h.setEncryptionMethod(JWA.A128CBC);
        final byte[] ivBytes = Hex.decode("cafebabefacedbaddecaf88813141516");
        h.setInitializationVector(Base64URL.encode(ivBytes));

        JSONObject claims = new JSONObject();
        claims.put("iss", "http://nimbusds.com");
        claims.put("exp", 123);
        claims.put("act", true);

        EncryptedJWT jwt = new EncryptedJWT(h, new ClaimsSet(claims));
        jwt.rsaEncrypt(publicKey);
        System.out.println(jwt.getState());
        System.out.println(jwt.serialize());

        String[] parts = jwt.serialize().split("\\.");
        System.out.println(new String(Base64.decodeBase64(parts[0])));
        System.out.println(parts[0]);

    }

//    /**
//     * RSA PKCS1 oracle test
//     */
//    public void testRSAPKCS1() throws Exception {
//        HTTPHandler h = new HTTPHandler();
//        String[] parts = test.split("\\.");
//        
//        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
//        
//        byte[] clear = new byte[64];
//        clear[0] = 0;
//        clear[1] = 2;
//
//        for (int i = 2; i < clear.length; i++) {
//            clear[i] = 1;
//        }
//        
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        clear[0] = 1;
//        byte[] cipherData = cipher.doFinal(clear);
//        clear[0] = 0;
//        parts[1] = new String(Base64.encodeBase64(cipherData));
//        String resp = h.sendMessage(parts[0] + "." + parts[1] + "." + parts[2] + ".", url);
//        System.out.println(resp);
//        
//        for (int i = 1; i < clear.length; i++) {
//            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//            clear[i] = 0;
//            cipherData = cipher.doFinal(clear);
//            clear[i] = 2;
//            parts[1] = new String(Base64.encodeBase64(cipherData));
//            resp = h.sendMessage(parts[0] + "." + parts[1] + "." + parts[2] + ".", url);
//            System.out.println(resp);
//        }
//    }
//    /**
//     * RSA PKCS1 oracle test
//     */
//    public void testCBC() throws Exception {
//        HTTPHandler h = new HTTPHandler();
//        String[] parts = test.split("\\.");
//        
//        System.out.println(new String(Base64.decodeBase64(parts[0])));
//        
//        byte[] cipher = Base64.decodeBase64(parts[2]);
//        
//        System.out.println(cipher.length);
//        
//        for (int i = 0; i < 256; i++) {
//            
//            cipher[cipher.length-17] = (byte) i;
//            parts[2] = new String(Base64.encodeBase64(cipher));
//            String resp = h.sendMessage(parts[0] + "." + parts[1] + "." + parts[2] + ".", url);
//            System.out.println(resp);
//        }
//    }
}
