/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.cryptochallenge.handlers;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import org.apache.log4j.Logger;

/**
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
abstract class PageHandler implements HttpHandler {

    String fileName;
    String page;
    static Logger logger = Logger.getRootLogger();

    String readPage() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(fileName));
            String line;
            StringBuilder sb = new StringBuilder();
            while ((line = br.readLine()) != null) {
                sb.append(line);
                sb.append("\r\n");
            }
            return sb.toString();
        } catch (IOException e) {
            logger.debug(e.getLocalizedMessage(), e);
            return "Error occured";
        }
    }
    
    public void handle(HttpExchange t) throws IOException {
        t.sendResponseHeaders(200, page.length());
        OutputStream os = t.getResponseBody();
        os.write(page.getBytes());
        os.close();
    }
}
