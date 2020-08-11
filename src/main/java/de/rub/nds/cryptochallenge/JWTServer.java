package de.rub.nds.cryptochallenge;

import com.sun.net.httpserver.HttpServer;
import de.rub.nds.cryptochallenge.handlers.HallOfFameHandler;
import de.rub.nds.cryptochallenge.handlers.IndexHandler;
import de.rub.nds.cryptochallenge.handlers.ServiceHandler;
import java.net.InetSocketAddress;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

public class JWTServer {

    private static String logfile = "logging.properties";
    private static String keystore = "keystore512.jks";
    private static String alias = "rub";
    private static char[] password = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    private static String port = "50080";
    static Logger logger = Logger.getRootLogger();

    public static void main(String[] args) throws Exception {

        PropertyConfigurator.configure(logfile);

        ServiceHandler sh;
        if (args.length == 0) {
            sh = new ServiceHandler(keystore, alias, password);
        } else if (args.length != 4) {
            System.out.println("Start the server with the following args: keystore, alias, password, server port");
            return;
        } else {
            sh = new ServiceHandler(args[0], args[1], args[2].toCharArray());
            port = args[3];
        }
        HttpServer server = HttpServer.create(new InetSocketAddress(Integer.parseInt(port)), 0);
        server.createContext("/", new IndexHandler());
        server.createContext("/index.html", new IndexHandler());
//        server.createContext("/hall-of-fame.html", new HallOfFameHandler());
        server.createContext("/service", sh);
        server.setExecutor(null); // creates a default executor
        server.start();

        logger.info("Server successfully started");
    }
}
