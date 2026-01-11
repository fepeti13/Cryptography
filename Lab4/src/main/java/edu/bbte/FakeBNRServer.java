package edu.bbte;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class FakeBNRServer {
    private static final int PORT = 443;
    private static final String KEYSTORE_PATH = "certificates/fake-bnr.p12";
    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String HTML_FILE = "bnr_response.html";

    public static void main(String[] args) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), trustAllCerts, null);

            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(PORT);

            System.out.println("Server running on port " + PORT);

            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                handleClient(socket);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(SSLSocket socket) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream());

            String request = in.readLine();
            System.out.println("Request received: " + request);

            while (in.readLine().length() > 0);

            String htmlContent = readHtmlFile();

            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html");
            out.println("Content-Length: " + htmlContent.length());
            out.println();
            out.println(htmlContent);
            out.flush();

            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String readHtmlFile() throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(HTML_FILE));
        StringBuilder content = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }

        reader.close();
        return content.toString();
    }
}