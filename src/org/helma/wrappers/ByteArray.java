package org.helma.wrappers;

import org.mozilla.javascript.*;
import org.mozilla.javascript.annotations.JSFunction;
import org.mozilla.javascript.annotations.JSGetter;
import org.mozilla.javascript.annotations.JSSetter;
import org.mozilla.javascript.annotations.JSConstructor;
import org.helma.util.ScriptUtils;

import java.io.InputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Arrays;

/**
 * <p>A growable wrapper around a Java byte array compliant to the ByteBuffer class defined
 * in the <a href="https://wiki.mozilla.org/ServerJS/Binary/B">Binary/B proposal</a>.
 * To register ByteBuffer as a host object in Rhino call the <code>defineClass()</code>
 * function with the class.</p>
 *
 * <pre><code>defineClass(org.helma.wrappers.ByteBuffer);</code></pre>
 *
 * <p>The ByteArray constructor can take several arguments. Have a look at the proposal for
 * details.</p>
 *
 * <p>When passed to a Java method that expects a byte array, ByteBuffer wrappers
 * are automatically unwrapped. use the {@link #unwrap()} method to explicitly get the
 * wrapped stream.</p>
 */
public class ByteArray extends ScriptableObject implements Wrapper {

    private byte[] bytes;
    private int length;

    private final static String CLASSNAME = "ByteArray";

    public ByteArray() {}

    public ByteArray(Scriptable scope, byte[] bytes) {
        this(scope, bytes, 0, bytes.length);
    }

    public ByteArray(Scriptable scope, byte[] bytes, int offset, int length) {
        super(scope, ScriptUtils.getClassOrObjectProto(scope, CLASSNAME));
        this.bytes = new byte[length];
        this.length = length;
        System.arraycopy(bytes, offset, this.bytes, 0, length);
    }

    @JSConstructor
    public ByteArray(Object arg, Object charset) {
        if (arg instanceof Wrapper) {
            arg = ((Wrapper) arg).unwrap();
        }
        if (charset != Undefined.instance) {
            if (!(arg instanceof String)) {
                throw ScriptRuntime.typeError("Expected string as first argument");
            } else if (!(charset instanceof String)) {
                throw ScriptRuntime.typeError("Expected string as second argument");
            }
            try {
                bytes = ((String) arg).getBytes((String) charset);
                length = bytes.length;
            } catch (UnsupportedEncodingException uee) {
                throw ScriptRuntime.typeError("Unsupported encoding: " + charset);
            }
        } else if (arg instanceof Number) {
            length = ((Number) arg).intValue();
            bytes = new byte[Math.max(length, 8)];
        } else if (arg instanceof NativeArray) {
            NativeArray array = (NativeArray) arg;
            Integer ids[] = array.getIndexIds();
            length = ids.length;
            bytes = new byte[Math.max(length, 8)];
            for (int id : ids) {
                Object value = array.get(id, array);
                put(id, this, value);
            }
        } else if (arg instanceof byte[]) {
            bytes = (byte[]) arg;
            length = bytes.length;
        } else if (arg instanceof InputStream) {
            InputStream in = (InputStream) arg;
            byte[] buffer = new byte[1024];
            int read, count = 0;
            try {
                while ((read = in.read(buffer, count, buffer.length - count)) > -1) {
                    count += read;
                    if (count == buffer.length) {
                        byte[] b = new byte[buffer.length * 2];
                        System.arraycopy(buffer, 0, b, 0, count);
                        buffer = b;
                    }
                }
                bytes = buffer;
                length = count;
                in.close();
            } catch (IOException iox) {
                throw ScriptRuntime.typeError("Error initalizing ByteArray from input stream: " + iox);
            }
        } else if (arg == Undefined.instance) {
            bytes = new byte[8];
            length = 0;
        } else {
            throw ScriptRuntime.typeError("Unsupported argument: " + arg);
        }
    }

    @Override
    public Object get(int index, Scriptable start) {
        if (index < 0 || index >= length) {
            return Undefined.instance;
        }
        return Integer.valueOf(0xff & bytes[index]);
    }

    @Override
    public boolean has(int index, Scriptable start) {
        return index >= 0 && index < length;
    }

    @Override
    public void put(int index, Scriptable start, Object value) {
        if (index < 0) {
            throw ScriptRuntime.typeError("Negative ByteArray index");
        }
        if (!(value instanceof Number)) {
            throw ScriptRuntime.typeError("Non-numeric ByteArray member: " + value);
        }
        if (index >= length) {
            setLength(index + 1);
        }
        int n = ((Number) value).intValue();
        bytes[index] = (byte) (0xff & n);
    }

    @JSGetter
    public int getLength() {
        return length;
    }

    @JSSetter
    public synchronized void setLength(Object length) {
        int l = ScriptUtils.toInt(length, -1);
        if (l < 0) {
            throw ScriptRuntime.typeError("Inappropriate ByteArray length");
        }
        setLength(l);
    }

    protected synchronized void setLength(int newLength) {
        if (newLength < length) {
            // if shrinking clear the old buffer
            Arrays.fill(bytes, newLength, length, (byte) 0);
        } else if (newLength > bytes.length) {
            // if growing make sure the buffer is large enough
            int newSize = Math.max(newLength, bytes.length * 2);
            byte[] b = new byte[newSize];
            System.arraycopy(bytes, 0, b, 0, length);
            bytes = b;
        }
        length = newLength;
    }

    @JSFunction
    public Object get(Object index) {
        int i = ScriptUtils.toInt(index, -1);
        if (i < 0 || i >= length) {
            return Undefined.instance;
        }
        return Integer.valueOf(0xff & bytes[i]);
    }

    @JSFunction
    public void set(Object index, int value) {
        int i = ScriptUtils.toInt(index, -1);
        if (i > -1) {
            if (i >= length) {
                setLength(i + 1);
            }
            bytes[i] = (byte) (0xff & value);
        }
    }

    @JSFunction
    public synchronized Object toByteArray(Object sourceCharset, Object targetCharset)
            throws UnsupportedEncodingException {
        String source = toCharset(sourceCharset);
        String target = toCharset(targetCharset);
        if (source != null && target != null) {
            String str = new String(bytes, 0, length, source);
            return new ByteArray(getParentScope(), str.getBytes(target));
        }
        return new ByteArray(getParentScope(), bytes, 0, length);
    }

    @JSFunction
    public synchronized Object toArray(Object charset)
            throws UnsupportedEncodingException {
        Object[] elements;
        String cs = toCharset(charset);
        if (cs != null) {
            String str = new String(bytes, 0, length, cs);
            elements = new Object[str.length()];
            for (int i = 0; i < elements.length; i++) {
                elements[i] = Integer.valueOf(str.charAt(i));
            }
        } else {
            elements = new Object[length];
            for (int i = 0; i < length; i++) {
                elements[i] = Integer.valueOf(0xff & bytes[i]);
            }
        }
        return Context.getCurrentContext().newArray(getParentScope(), elements);
    }

    @JSFunction
    public Object slice(Object begin, Object end) {
        if (begin == Undefined.instance && end == Undefined.instance) {
            return new ByteArray(getParentScope(), bytes, 0, length);
        }
        int from = ScriptUtils.toInt(begin, 0);
        if (from < 0) {
            from = length + from;
        }
        from = Math.min(length, Math.max(0, from));
        int to = end == Undefined.instance ? length : ScriptUtils.toInt(end, from);
        int len = Math.max(0, Math.min(length - from,  to - from));
        return new ByteArray(getParentScope(), bytes, from, len);
    }

    @JSFunction
    public String decodeToString(Object charset) {
        String cs = toCharset(charset);
        try {
            return cs == null ?
                    new String(bytes, 0, length) : 
                    new String(bytes, 0, length, cs);
        } catch (UnsupportedEncodingException uee) {
            throw ScriptRuntime.typeError("Unsupported encoding: " + charset);
        }
    }

    @JSFunction
    public int indexOf(int n, Object from, Object to) {
        int start = Math.max(0, Math.min(length - 1, ScriptUtils.toInt(from, 0)));
        int end = Math.max(0, Math.min(length, ScriptUtils.toInt(to, length)));
        byte b = (byte) (0xff & n);
        for (int i = start; i < end; i++) {
            if (bytes[i] == b)
                return i;
        }
        return -1;
    }

    @JSFunction
    public int lastIndexOf(int n, Object from, Object to) {
        int start = Math.max(0, Math.min(length - 1, ScriptUtils.toInt(from, 0)));
        int end = Math.max(0, Math.min(length, ScriptUtils.toInt(to, length)));
        byte b = (byte) (0xff & n);
        for (int i = end - 1; i >= start; i--) {
            if (bytes[i] == b)
                return i;
        }
        return -1;
    }

    @JSFunction
    public synchronized Object split(Object delim, Object options) {
        byte[][] delimiters = getSplitDelimiters(delim);
        boolean includeDelimiter = false;
        if (options instanceof Scriptable) {
            Scriptable o = (Scriptable) options;
            Object include = o.get("includeDelimiter", o);
            includeDelimiter = o != NOT_FOUND && ScriptRuntime.toBoolean(include);
        }
        List<ByteArray> list = new ArrayList<ByteArray>();
        Scriptable scope = getParentScope();
        int index = 0;
        outer:
        for (int i = 0; i < length; i++) {
            inner:
            for (byte[] delimiter : delimiters) {
                if (i + delimiter.length > length) {
                    continue;
                }
                for (int j = 0; j < delimiter.length; j++) {
                    if (bytes[i + j] != delimiter[j]) {
                        continue inner;
                    }
                }
                list.add(new ByteArray(scope, bytes, index, i - index));
                if (includeDelimiter) {
                    list.add(new ByteArray(scope, delimiter));
                }
                index = i + delimiter.length;
                i = index - 1;
                continue outer;
            }
        }
        if (index == 0) {
            list.add(this);
        } else {
            list.add(new ByteArray(scope, bytes, index, length - index));
        }
        return Context.getCurrentContext().newArray(scope, list.toArray());
    }

    @JSFunction("unwrap")
    public Object jsunwrap() {
        return NativeJavaArray.wrap(getParentScope(), getBytes());
    }

    /**
     * Unwrap the object by returning the wrapped value.
     *
     * @return a wrapped value
     */
    public Object unwrap() {
        return getBytes();
    }

    public byte[] getBytes() {
        normalize();
        return bytes;
    }

    public String getClassName() {
        return CLASSNAME;
    }

    protected synchronized void ensureLength(int minLength) {
        if (minLength > length) {
            setLength(minLength);
        }
    }

    private synchronized void normalize() {
        if (length != bytes.length) {
            byte[] b = new byte[length];
            System.arraycopy(bytes, 0, b, 0, length);
            bytes = b;
        }
    }

    private byte[][] getSplitDelimiters(Object delim) {
        List<byte[]> list = new ArrayList<byte[]>();
        if (delim instanceof NativeArray) {
            Collection values = ((NativeArray) delim).values();
            for (Object value : values) {
                if (value instanceof Number) {
                    list.add(new byte[] {(byte) (0xff & ((Number) value).intValue())});
                } else if (value instanceof ByteArray) {
                    list.add(((ByteArray) value).getBytes());
                } else {
                    throw new RuntimeException("unsupported delimiter: " + value);
                }
            }
        } else if (delim instanceof Number) {
            list.add(new byte[] {(byte) (0xff & ((Number) delim).intValue())});
        } else if (delim instanceof ByteArray) {
            list.add(((ByteArray) delim).getBytes());
        } else {
            throw new RuntimeException("unsupported delimiter: " + delim);
        }
        return list.toArray(new byte[list.size()][]);
    }

    private String toCharset(Object charset) {
        if (charset != Undefined.instance && !(charset instanceof String)) {
            throw ScriptRuntime.typeError("Unsupported charset: " + charset);
        }
        return charset instanceof String ? (String) charset : null;
    }
}