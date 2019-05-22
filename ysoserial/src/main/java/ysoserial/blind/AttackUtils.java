package ysoserial.blind;

import ysoserial.Log;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.util.ArrayList;

/**
 * Helper utilities for the Attack class.
 *
 * Created by dusanklinec on 17.09.16.
 */
public class AttackUtils {
    /**
     * Performs synchronous HTTP GET request, returns the response.
     *
     * @param urlToRead
     * @return
     * @throws Exception
     */
    public static String httpGet(String urlToRead) throws Exception {
        return httpGet(urlToRead, Proxy.NO_PROXY);
    }

    public static String httpGet(String urlToRead, Proxy proxy) throws Exception {
        StringBuilder result = new StringBuilder();
        URL url = new URL(urlToRead);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
        conn.setRequestMethod("GET");
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        rd.close();
        return result.toString();
    }

    /**
     * Performs synchronous HTTP POST request with raw data, returns the response.
     * @param urlToRead
     * @param post
     * @return
     * @throws Exception
     */
    public static String httpPost(String urlToRead, String post) throws Exception {
        return httpPost(urlToRead, post, Proxy.NO_PROXY);
    }

    private static HttpURLConnection con;
    public static String httpPostWithBinary(String urlToRead, byte[] post) throws Exception {

        StringBuilder content;
        try {
            URL myurl = new URL(urlToRead);
            installForgivingSSLSocketFactory();
//            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));


            con = (HttpURLConnection) myurl.openConnection();

            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("User-Agent", "Java client");
            con.setRequestProperty("Content-Type", "");
//
            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {

                wr.write(post);
            }



            try (BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()))) {

                String line;
                content = new StringBuilder();

                while ((line = in.readLine()) != null) {
                    content.append(line);
                    content.append(System.lineSeparator());
                }
            }

            System.out.println(content.toString());

        } finally {

            con.disconnect();
        }
        return content.toString();
    }

    public static String httpPost(String urlToRead, String post, Proxy proxy) throws Exception {
        StringBuilder result = new StringBuilder();
        URL url = new URL(urlToRead);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection(proxy);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        final OutputStream os = conn.getOutputStream();
        final BufferedOutputStream bos = new BufferedOutputStream(os);

        String data = URLEncoder.encode(post, "UTF-8");

        bos.write(data.getBytes("UTF-8"));
        bos.close();

        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        rd.close();
        return result.toString();
    }

    /**
     * Sets default SSLSocketFactory to HttpsURLConnection which performs no SSL
     * certificate validation and hostname verification.
     * Useful if the target does not have a valid certificate (e.g., selfsigned localhost).
     */
    public static void installForgivingSSLSocketFactory(){
        HttpsURLConnection.setDefaultSSLSocketFactory(forgivingSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((s, sslSession) -> false);
    }

    public static SSLSocketFactory forgivingSocketFactory(){
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, forgivingTrustManager(), new java.security.SecureRandom());
            return sc.getSocketFactory();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static TrustManager[] forgivingTrustManager(){
        return new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
    }

    /**
     * Generates REGEX for string.matches() with the whole ASCII alphabet we are interested in:
     * chr(32 - 127) + whitespaces (tab, new line, space)
     *
     * The ordering could be basically arbitrary as we do the binary search on the alphabet indices.
     *
     * @return
     */
    public static ArrayList<String> generateAsciiRegexAlphabet(boolean regex){
        ArrayList<String> alphabet = new ArrayList<>();
        alphabet.add("\\x00");
        alphabet.add(regex ? "\\x09" : "    "); // horizontal tab
        alphabet.add(regex ? "\\x0a" : "\n"); // line feed
        alphabet.add("\\x0b"); // vertical tab
        alphabet.add("\\x0c"); // form feed
        alphabet.add(regex ? "\\x0d" : "\r"); // carriage return

        for(int c = 33; c <= 126; c++){
            String curChar = Character.toString((char) c);
            if (!regex){
                alphabet.add(curChar);
                continue;
            }

            if (c == 46 || c == 45 || c == 94 || c == 91 || c == 93 || c == 40 || c == 41 || c ==123 || c==124||c==125){
                curChar = "\\" + curChar;
            } else if (c == 92){
                curChar = "\\\\";
            } else if (c == 34){
                curChar = "\\" + curChar;
            }

            alphabet.add(curChar);
        }

        // Speed optimization, right part is not waited on. Space is quite common...
        alphabet.add(regex ? "\\s" : " ");   // white space

        return alphabet;
    }

    /**
     * Generates REGEX for string.matches() with the whole ASCII alphabet we are interested in:
     * chr(32 - 127) + whitespaces (tab, new line, space)
     *
     * The ordering could be basically arbitrary as we do the binary search on the alphabet indices.
     *
     * @return
     */
    public static ArrayList<String> generateAsciiRegexAlphabet(){
        return generateAsciiRegexAlphabet(true);
    }

    /**
     * Generates complete one character alphabet for bisection.
     * @return
     */
    public static ArrayList<String> generateFullRegexAlphabet(boolean regex){
        ArrayList<String> alphabet = new ArrayList<>(256);
        for(int c = 0; c <= 0xff; c++){
            if (regex) {
                alphabet.add(String.format("\\x%02d", c));
            } else {
                alphabet.add(String.format("%02d", c));
            }
        }

        return alphabet;
    }
}
