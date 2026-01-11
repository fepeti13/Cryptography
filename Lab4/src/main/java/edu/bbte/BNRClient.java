package edu.bbte;

import javax.net.ssl.*;
import java.io.*;

public class BNRClient {
    public static void main(String[] args) {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

            System.out.println("Kapcsolódás a bnr.ro szerverhez...");
            SSLSocket socket = (SSLSocket) factory.createSocket("bnr.ro", 443);

            PrintWriter out = new PrintWriter(socket.getOutputStream());
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            System.out.println("HTTP GET kérés küldése...");
            out.println("GET /Home.aspx HTTP/1.1");
            out.println("Host: bnr.ro");
            out.println("Connection: close");
            out.println();
            out.flush();

            System.out.println("\nVálasz:");
            String line;
            int count = 0;
            while ((line = in.readLine()) != null && count++ < 20) {
                System.out.println(line);
            }

            socket.close();
            System.out.println("\nKapcsolat lezárva.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}