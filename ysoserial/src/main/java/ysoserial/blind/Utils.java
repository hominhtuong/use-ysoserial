package ysoserial.blind;

import org.hjson.JsonValue;
import org.json.JSONException;
import org.json.JSONObject;
import ysoserial.Log;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

/**
 * Created by dusanklinec on 04.09.16.
 */
public class Utils {
    public static String base64UrlFriendly(String base){
        return base.replace("+", "-").replace("/", "_").replace("=", "");
    }

    public static String base64UrlFriendly(byte[] buff){

        return base64UrlFriendly(base64(buff));
    }

    public static String base64(byte[] buff){
        return new String(Base64.getEncoder().encode(buff));
        //return DatatypeConverter.printBase64Binary(buff);
    }

    public static JSONObject parseJSON(String json){
        try {
            return new JSONObject(JsonValue.readHjson(json).toString());
        } catch(org.hjson.ParseException e) {
            System.out.println(json);
            throw e;
        }
    }

    /**
     * Tries to extract json parameter as an integer.
     * @param json target
     * @param key field name
     * @return extracted boolean
     * @throws JSONException
     */
    public static Boolean tryGetAsBoolean(JSONObject json, String key) throws JSONException {
        final Object obj = json.get(key);
        if (obj == null){
            return null;
        }

        if(!obj.equals(Boolean.FALSE) && (!(obj instanceof String) || !((String)obj).equalsIgnoreCase("false"))) {
            if(!obj.equals(Boolean.TRUE) && (!(obj instanceof String) || !((String)obj).equalsIgnoreCase("true"))) {
                final Integer asInt = tryGetAsInteger(json, key, 10);
                if (asInt == null){
                    return null;
                }

                return asInt!=0;

            } else {
                return true;
            }
        } else {
            return false;
        }
    }

    /**
     * Tries to extract json parameter as a string.
     * If parameter is not present or is not a string, null is returned.
     *
     * @param json target
     * @param key field name
     * @return extracted string
     */
    public static JSONObject getAsJSON(JSONObject json, String key) {
        if (!json.has(key)){
            return null;
        }

        try {
            return (json.getJSONObject(key));
        } catch(JSONException e){
            return null;
        }
    }

    /**
     * Tries to extract json parameter as a string.
     * If parameter is not present or is not a string, null is returned.
     *
     * @param json target
     * @param key field name
     * @return extracted string
     */
    public static String getAsString(JSONObject json, String key) {
        if (!json.has(key)){
            return null;
        }

        try {
            return (json.getString(key));
        } catch(JSONException e){
            return null;
        }
    }

    public static String getAsString(JSONObject json, String key, String def){
        final String res = getAsString(json, key);
        return res != null ? res : def;
    }

    /**
     * Tries to extract json parameter as an string.
     * @param json target
     * @param key field name
     * @return extracted string
     * @throws JSONException - if the JSON object doesn't contain the item or is malformed
     */
    public static String tryGetAsString(JSONObject json, String key) throws JSONException {
        return json.getString(key);
    }

    /**
     * Tries to extract json parameter as an integer.
     * @param json target
     * @param key field name
     * @param radix radix for string / int conversion
     * @return extracted integer
     * @throws JSONException - if the JSON object doesn't contain the item or is malformed
     */
    public static Integer tryGetAsInteger(JSONObject json, String key, int radix) throws JSONException {
        final Object obj = json.get(key);

        if (obj instanceof String){
            try {
                return Integer.parseInt((String) obj, radix);
            } catch(Exception e){
                return null;
            }
        }

        try {
            return obj instanceof Number ? ((Number) obj).intValue() : (int) json.getDouble(key);
        } catch(Exception e){
            return null;
        }
    }

    /**
     * Tries to extract json parameter as a long.
     * @param json target
     * @param key field name
     * @param radix radix for string / int conversion
     * @return extracted long
     * @throws JSONException - if the JSON object doesn't contain the item or is malformed
     */
    public static Long tryGetAsLong(JSONObject json, String key, int radix) throws JSONException {
        final Object obj = json.get(key);

        if (obj instanceof String){
            try {
                return Long.parseLong((String) obj, radix);
            } catch(Exception e){
                return null;
            }
        }

        try {
            return obj instanceof Number ? ((Number) obj).longValue() : (long) json.getDouble(key);
        } catch(Exception e){
            return null;
        }
    }

    public static long getAsLong(JSONObject json, String key, int radix) throws JSONException {
        final Long toret = tryGetAsLong(json, key, radix);
        if (toret == null) {
            throw new JSONException("JSONObject[" + key + "] not found.");
        }

        return toret;
    }

    public static int getAsInteger(JSONObject json, String key, int radix) throws JSONException {
        final Integer toret = tryGetAsInteger(json, key, radix);
        if (toret == null) {
            throw new JSONException("JSONObject[" + key + "] not found.");
        }

        return toret;
    }

    public static boolean getAsBoolean(JSONObject json, String key) throws JSONException {
        final Boolean toret = tryGetAsBoolean(json, key);
        if (toret == null) {
            throw new JSONException("JSONObject[" + key + "] not found.");
        }

        return toret;
    }

    /**
     * Merges JSON objects into collection
     * @return resulting array, new one, not null.
     */
    public static List<JSONObject> merge(Collection<JSONObject> first, Collection<JSONObject>... rest){
        final ArrayList<JSONObject> res = new ArrayList<>();
        if (first != null) {
            res.addAll(first);
        }

        if (rest != null){
            for(Collection<JSONObject> col : rest){
                res.addAll(col);
            }
        }

        return res;
    }

    /**
     * Merges JSON objects into collection
     * @return resulting array, new one, not null.
     */
    public static List<JSONObject> merge(JSONObject first, JSONObject... rest){
        final ArrayList<JSONObject> res = new ArrayList<>();
        if (first != null) {
            res.add(first);
        }

        if (rest != null){
            for(JSONObject col : rest){
                res.add(col);
            }
        }

        return res;
    }

    /**
     * Merges JSON objects into collection
     * @return resulting array, new one, not null.
     */
    public static List<JSONObject> merge(Collection<JSONObject> a, JSONObject b){
        final ArrayList<JSONObject> res = new ArrayList<>();
        if (a != null){
            res.addAll(a);
        }
        if (b != null){
            res.add(b);
        }
        return res;
    }

    /**
     * Merges JSON objects into collection
     * @return resulting array, new one, not null.
     */
    public static List<JSONObject> merge(JSONObject a, Collection<JSONObject> b){
        return merge(b, a);
    }
}
