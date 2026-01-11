package edu.bbte;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

public class BNRClient {
    public static void main(String[] args) {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

            URL url = new URL("https://bnr.ro/");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            connection.setRequestProperty("Accept", "text/html");
            connection.connect();

            Certificate[] certs = connection.getServerCertificates();

            for (int i = 0; i < certs.length; i++) {
                X509Certificate cert = (X509Certificate) certs[i];

                System.out.println("Certificate " + (i + 1));
                System.out.println("Version: " + cert.getVersion());
                System.out.println("Serial: " + cert.getSerialNumber().toString(16));
                System.out.println("Issuer: " + cert.getIssuerX500Principal().getName());
                System.out.println("Valid from: " + cert.getNotBefore());
                System.out.println("Valid until: " + cert.getNotAfter());
                System.out.println("Subject: " + cert.getSubjectX500Principal().getName());
                System.out.println("Public key algorithm: " + cert.getPublicKey().getAlgorithm());
                System.out.println("Signature algorithm: " + cert.getSigAlgName());

                String pubKey = java.util.Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded());
                System.out.println("Public key: " + pubKey.substring(0, 80) + "...");

                System.out.println();
            }

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            FileWriter fileWriter = new FileWriter("bnr_response.html");
            BufferedWriter out = new BufferedWriter(fileWriter);

            String line;
            while ((line = in.readLine()) != null) {
                out.write(line);
                out.newLine();
            }

            out.close();
            in.close();
            connection.disconnect();

            System.out.println("HTML saved to bnr_response.html");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}