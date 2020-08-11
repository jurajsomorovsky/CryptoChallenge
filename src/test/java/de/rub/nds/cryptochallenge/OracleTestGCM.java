package de.rub.nds.cryptochallenge;

import com.nimbusds.jwt.Base64URL;
import com.nimbusds.jwt.ClaimsSet;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.Header;
import com.nimbusds.jwt.JWA;
import com.nimbusds.jwt.JWEHeader;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
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
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
public class OracleTestGCM
        extends TestCase {

    private static String logfile = "logging.properties";
    private static String keystore = "keystore512.jks";
    private static String alias = "rub";
    private static char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    static Logger logger = Logger.getRootLogger();
    private final static String test = "eyJhbGciOiJSU0FfT0FFUCIsIml2IjoieXY2NnZ2ck8yNjNleXZpSSIsInR5cCI6IkpXVCIsImVuYyI6IkExMjhHQ00ifQ==.\r\nZBnPlwONWHxGDrtCxxopS4y4SrMZIAhUg3HI+SbLMxfPVRPW8yunejrkmfSLO1H/0tOx4ssggygHjG7sUfxL8A==.i2vygn2vqFpsmep3etrD5Yh5xLP9xYhJdvn63WmHEPYChA==.";
    private final static String url = "http://cryptochallenge.nds.rub.de:50080/service";
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
    private final byte[] firstPlaintextJWT = {16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16};
    private final byte[] secondPlaintextJWT = {0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15};

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public OracleTestGCM(String testName) throws KeyStoreException, IOException, NoSuchAlgorithmException,
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
        return new TestSuite(OracleTestGCM.class);
    }

    public void testEncryptJWTClaims() throws Exception {
        JWEHeader h = new JWEHeader(JWA.RSA_OAEP);
        h.setType(Header.Type.JWT);
        h.setEncryptionMethod(JWA.A128GCM);
        final byte[] ivBytes = Hex.decode("cafebabefacedbaddecaf888");
        h.setInitializationVector(Base64URL.encode(ivBytes));

        JSONObject claims = new JSONObject();
        claims.put("My PIN:", "5983");

        EncryptedJWT jwt = new EncryptedJWT(h, new ClaimsSet(claims));
        jwt.rsaEncrypt(publicKey);
        System.out.println(jwt.getState());
        System.out.println(jwt.serialize());

        String[] parts = jwt.serialize().split("\\.");
        System.out.println(new String(Base64.decodeBase64(parts[0])));

        System.out.println(Base64.decodeBase64(parts[2]).length);
        byte[] sk = decryptOAEP(Base64.decodeBase64(parts[1]));

        byte[] p = decryptGCM(h.getInitializationVector().decode(), sk, Base64.decodeBase64(parts[2]));

        System.out.println(new String(p));
    }

    public byte[] decryptOAEP(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(ciphertext);
    }

    public byte[] decryptGCM(byte[] iv, byte[] key, byte[] ciphertext) throws Exception {
        SecretKeySpec k = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        cipher.init(Cipher.DECRYPT_MODE, k, ivSpec);
        return cipher.doFinal(ciphertext);
    }

//    /**
//     * RSA PKCS1 oracle test
//     */
//    public void testRSAPKCS1_OAEP() throws Exception {
//        HTTPHandler h = new HTTPHandler();
//        String[] parts = test.split("\\.");
//
//        String currentAlgs = new String(Base64.decodeBase64(parts[0]));
//        String newAlgs = currentAlgs.replaceAll("RSA_OAEP", "RSA1_5");
//        newAlgs = newAlgs.replaceAll("A128GCM", "A128CBC");
//        newAlgs = newAlgs.replaceAll("yv66vvrO263eyviI", new String(Base64.encodeBase64(new byte[16])));
//        System.out.println(newAlgs);
//
//        parts[0] = new String(Base64.encodeBase64(newAlgs.getBytes()));
//
//        BigInteger msg = new BigInteger(Base64.decodeBase64(parts[0]));
//        BigInteger mod = publicKey.getModulus();
//        BigInteger si = BigInteger.ONE;
//
//        for (int i = 0; i < 10000; i++) {
//            si = si.add(BigInteger.TEN);
//            BigInteger tmp;
//
//            // encrypt: si^e mod n
//            tmp = si.modPow(publicKey.getPublicExponent(), mod);
//
//            // blind: c0*(si^e) mod n
//            // or: m*si mod n (in case of plaintext oracle)
//            tmp = msg.multiply(tmp);
//            tmp = tmp.mod(publicKey.getModulus());
//
//            byte[] c = correctSize(tmp.toByteArray(), 64, true);
//
//            parts[1] = new String(Base64.encodeBase64(c));
//            String resp = h.sendMessage(parts[0] + "." + parts[1] + "." + parts[2] + ".", url);
//            System.out.println(resp);
//
//        }
//    }

    /**
     * RSA PKCS1 oracle test
     */
    public void testCBC() throws Exception {

        HTTPHandler h = new HTTPHandler();
        String[] parts = test.split("\\.");

        String currentAlgs = new String(Base64.decodeBase64(parts[0]));
        String newAlgs = currentAlgs.replaceAll("A128GCM", "A128CBC");

        String plaintext = "{\"My PIN:\":\"5983";
        byte[] plain = plaintext.getBytes();

        byte[] oldBlock = Arrays.copyOf(Base64.decodeBase64(parts[2]), 16);
        byte[] newBlock = xorArrays(plain, oldBlock);
        parts[2] = new String(Base64.encodeBase64(newBlock));
        
        System.out.println(Base64.encodeBase64(newBlock).length);

        byte[] cbcMid = new byte[16];
        byte[] gcmIv = Base64.decodeBase64("yv66vvrO263eyviI");
        for (int i = 0; i < cbcMid.length; i++) {
            if (i < gcmIv.length) {
                cbcMid[i] = gcmIv[i];
            } else {
                cbcMid[i] = 0;
            }
        }
        cbcMid[cbcMid.length-1] = 2;
        
        byte[] iv = xorArrays(cbcMid, firstPlaintextJWT);
//        iv[0] = 2;
        
        newAlgs = newAlgs.replaceAll("yv66vvrO263eyviI", new String(Base64.encodeBase64(iv)));

        parts[0] = new String(Base64.encodeBase64(newAlgs.getBytes()));
        System.out.println(newAlgs);
        
        System.out.println(parts[0] + "." + parts[1] + "." + parts[2]);
        System.out.println(Base64.decodeBase64(parts[2]).length);

        String resp = h.sendMessage(parts[0] + "." + parts[1] + "." + parts[2] + ".", url);
        System.out.println(resp);
    }

    /**
     * Corrects the length of a byte array to a multiple of a passed blockSize.
     *
     * @param array Array which size should be corrected
     * @param blockSize Blocksize - the resulting array length will be a
     * multiple of it
     * @param removeSignByte If set to TRUE leading sign bytes will be removed
     * @return Size corrected array (maybe padded or stripped the sign byte)
     */
    public static byte[] correctSize(final byte[] array, int blockSize,
            boolean removeSignByte) {
        int remainder = array.length % blockSize;
        byte[] result = array;
        byte[] tmp;

        if (removeSignByte && remainder > 0 && result[0] == 0x0) {
            // extract signing byte if present
            tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
            remainder = tmp.length % blockSize;
        }

        if (remainder > 0) {
            // add zeros to fit size
            tmp = new byte[result.length + blockSize - remainder];
            System.arraycopy(result, 0, tmp, blockSize - remainder,
                    result.length);
            result = tmp;
        }

        return result;
    }

    public static byte[] xorArrays(byte[] a1, byte[] a2) {
        byte[] xor = new byte[16];
        for (int i = 0; i < xor.length; i++) {
            xor[i] = (byte) (a1[i] ^ a2[i]);
        }
        return xor;
    }
}
