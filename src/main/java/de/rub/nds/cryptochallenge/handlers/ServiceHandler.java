/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.cryptochallenge.handlers;

import com.nimbusds.jwt.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWEException;
import com.nimbusds.jwt.JWTException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import org.apache.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class ServiceHandler implements HttpHandler {

    private RSAPrivateKey key;
    static Logger logger = Logger.getRootLogger();
    private long requestNumber =0;

    public ServiceHandler(String keyStoreFile, String alias, char[] password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(keyStoreFile);
            keyStore.load(fis, password);
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        key = (RSAPrivateKey) keyStore.getKey(alias, password);
    }

    public void handle(HttpExchange t) throws IOException {
        
        requestNumber++;
        logger.info("Request number: " + requestNumber + " IP:port: " + t.getRemoteAddress().toString());

        BufferedReader br = new BufferedReader(new InputStreamReader(t.getRequestBody()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }

        String[] parts = sb.toString().split("\\.");

        Base64URL[] base64 = new Base64URL[4];
        for (int i = 0; i < 3; i++) {
            if (parts.length <= i) {
                base64[i] = new Base64URL("");
            } else {
                base64[i] = new Base64URL(parts[i]);
            }
        }

        String returnValue = "";

        try {
            EncryptedJWT ejwt = new EncryptedJWT(base64[0], base64[1], base64[2], base64[3]);
            ejwt.rsaDecrypt(key);
            returnValue = "Data successfully stored";
            logger.debug("data successfully decrypted");
        } catch (JWTException e) {
            logger.debug(e.getLocalizedMessage(), e);
            returnValue = "Unknown exception";
        } catch (JWEException e) {
            logger.debug(e.getLocalizedMessage(), e);
            returnValue = e.getLocalizedMessage();
        }

        t.sendResponseHeaders(200, returnValue.length());
        OutputStream os = t.getResponseBody();
        os.write(returnValue.getBytes());
        os.close();
    }
}
