package ysoserial.blind;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Takes care about merging elements into one list / array.
 *
 * Created by dusanklinec on 19.09.16.
 */
public class Merger<T> {
    private final List<T> elements = new LinkedList<T>();
    private Class cls = null;

    public Merger(){

    }

    public Merger(T[] item, T[] ... rest){
        add(item, rest);
    }

    public Merger(Collection<T> item, Collection<T> ... rest){
        add(item, rest);
    }

    public Merger(T item, T ... rest){
        add(item, rest);
    }

    public Merger<T> add(T[] item, T[] ... rest){
        if (item != null){
            Collections.addAll(elements, item);
        }

        if (rest != null){
            for (T[] aRest : rest) {
                Collections.addAll(elements, aRest);
            }
        }

        return this;
    }

    public Merger<T> add(Collection<T> item, Collection<T> ... rest){
        if (item != null){
            elements.addAll(item);
        }

        if (rest != null){
            for (Collection<T> aRest : rest) {
                elements.addAll(aRest);
            }
        }

        return this;
    }

    public Merger<T> add(T item, T ... rest){
        if (item != null){
            elements.add(item);
        }

        if (rest != null){
            for (T aRest : rest) {
                elements.add(aRest);
            }
        }
        return this;
    }

    public Merger<T> cls(Class cls){
        this.cls = cls;
        return this;
    }

    public List<T> get(){
        return Collections.unmodifiableList(elements);
    }

    public T[] toArray(){
        if (cls == null){
            return (T[]) elements.toArray();
        } else {
            final T[] arr = (T[]) Array.newInstance(cls, elements.size());
            return elements.toArray(arr);
        }
    }

    public T[] toArray(Class cls){
        final T[] arr = (T[]) Array.newInstance(cls, elements.size());
        return elements.toArray(arr);
    }
}
