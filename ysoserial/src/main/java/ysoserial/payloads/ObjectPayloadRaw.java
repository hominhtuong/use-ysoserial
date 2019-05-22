package ysoserial.payloads;


import org.reflections.Reflections;
import ysoserial.GeneratePayload;

import java.lang.reflect.Modifier;
import java.util.Iterator;
import java.util.Set;


@SuppressWarnings ( "rawtypes" )
public interface ObjectPayloadRaw<T> {

    /*
     * return armed payload object to be serialized that will execute specified
     * command on deserialization
     */
    public T getObject(Object command) throws Exception;

    public static class Utils {

        // get payload classes by classpath scanning
        public static Set<Class<? extends ObjectPayloadRaw>> getPayloadClasses () {
            final Reflections reflections = new Reflections(ObjectPayloadRaw.class.getPackage().getName());
            final Set<Class<? extends ObjectPayloadRaw>> payloadTypes = reflections.getSubTypesOf(ObjectPayloadRaw.class);
            for (Iterator<Class<? extends ObjectPayloadRaw>> iterator = payloadTypes.iterator(); iterator.hasNext(); ) {
                Class<? extends ObjectPayloadRaw> pc = iterator.next();
                if ( pc.isInterface() || Modifier.isAbstract(pc.getModifiers()) ) {
                    iterator.remove();
                }
            }
            return payloadTypes;
        }


        @SuppressWarnings ( "unchecked" )
        public static Class<? extends ObjectPayloadRaw> getPayloadClass (final String className ) {
            Class<? extends ObjectPayloadRaw> clazz = null;
            try {
                clazz = (Class<? extends ObjectPayloadRaw>) Class.forName(className);
            }
            catch ( Exception e1 ) {}
            if ( clazz == null ) {
                try {
                    return clazz = (Class<? extends ObjectPayloadRaw>) Class
                            .forName(GeneratePayload.class.getPackage().getName() + ".payloads." + className);
                }
                catch ( Exception e2 ) {}
            }
            if ( clazz != null && !ObjectPayloadRaw.class.isAssignableFrom(clazz) ) {
                clazz = null;
            }
            return clazz;
        }


        public static Object makePayloadObject ( String payloadType, String payloadArg ) {
            final Class<? extends ObjectPayloadRaw> payloadClass = getPayloadClass(payloadType);
            if ( payloadClass == null || !ObjectPayloadRaw.class.isAssignableFrom(payloadClass) ) {
                throw new IllegalArgumentException("Invalid payload type '" + payloadType + "'");

            }

            final Object payloadObject;
            try {
                final ObjectPayloadRaw payload = payloadClass.newInstance();
                payloadObject = payload.getObject(payloadArg);
            }
            catch ( Exception e ) {
                throw new IllegalArgumentException("Failed to construct payload", e);
            }
            return payloadObject;
        }


        @SuppressWarnings ( "unchecked" )
        public static void releasePayload (ObjectPayloadRaw payload, Object object ) throws Exception {
            if ( payload instanceof ReleaseableObjectPayload ) {
                ( (ReleaseableObjectPayload) payload ).release(object);
            }
        }


        public static void releasePayload ( String payloadType, Object payloadObject ) {
            final Class<? extends ObjectPayloadRaw> payloadClass = getPayloadClass(payloadType);
            if ( payloadClass == null || !ObjectPayloadRaw.class.isAssignableFrom(payloadClass) ) {
                throw new IllegalArgumentException("Invalid payload type '" + payloadType + "'");

            }

            try {
                final ObjectPayloadRaw payload = payloadClass.newInstance();
                releasePayload(payload, payloadObject);
            }
            catch ( Exception e ) {
                e.printStackTrace();
            }

        }
    }
}
