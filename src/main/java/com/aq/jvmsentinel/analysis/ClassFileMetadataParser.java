package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.analysis.ClassMetadata.AnnotationMetadata;
import com.aq.jvmsentinel.analysis.ClassMetadata.MethodMetadata;
import com.aq.jvmsentinel.analysis.ClassMetadata.ParameterMetadata;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, bounded classfile parser. It intentionally understands only the
 * constant-pool and annotation-related structures needed by pre-analysis.
 */
final class ClassFileMetadataParser {
    private static final int MAX_CONSTANT_POOL_ENTRIES = 65_535;
    private static final int MAX_UTF8_BYTES = 16_384;
    private static final int MAX_MEMBERS = 16_384;
    private static final int MAX_ATTRIBUTES = 1_024;
    private static final int MAX_ANNOTATIONS = 512;
    private static final int MAX_ANNOTATION_PAIRS = 128;
    private static final int MAX_ARRAY_VALUES = 256;
    private static final int MAX_VALUE_DEPTH = 8;
    private static final int MAX_TOTAL_VALUES = 8_192;
    private static final int MAX_TOTAL_ANNOTATIONS = 8_192;
    private static final int MAX_TOTAL_ATTRIBUTES = 16_384;
    private static final int MAX_TOTAL_PARAMETERS = 20_000;
    private static final int MAX_VALUE_LENGTH = 512;

    private ClassFileMetadataParser() { }

    static ClassMetadata parse(byte[] bytes, String fallbackClassName) {
        try {
            return new Parser(bytes).parse();
        } catch (MalformedClassFile ignored) {
            return ClassMetadata.invalid(fallbackClassName);
        } catch (RuntimeException ignored) {
            // Parser defects and malformed lengths must not escape as allocation
            // requests or turn an invalid class into executable behavior.
            return ClassMetadata.invalid(fallbackClassName);
        }
    }

    private static final class Parser {
        private final Cursor input;
        private Object[] constantPool;
        private byte[] constantTags;
        private int totalValues;
        private int totalAnnotations;
        private int totalAttributes;
        private int totalParameters;

        private Parser(byte[] bytes) {
            input = new Cursor(bytes, 0, bytes.length);
        }

        private ClassMetadata parse() {
            if (input.u4() != 0xCAFEBABEL) fail();
            input.u2(); // minor
            int major = input.u2();
            if (major < 45 || major > 100) fail();
            parseConstantPool();
            input.u2(); // access_flags
            int thisClass = input.u2();
            input.u2(); // super_class
            String className = className(thisClass);
            int interfaces = bounded(input.u2(), MAX_MEMBERS);
            input.skip((long) interfaces * 2);
            skipMembers(input);
            List<MutableMethod> methods = parseMethods();
            List<AnnotationMetadata> classAnnotations = new ArrayList<>();
            parseAttributes(input, (name, body) -> {
                if (isAnnotationAttribute(name)) classAnnotations.addAll(parseAnnotations(body));
            });
            if (input.remaining() != 0) fail();
            List<MethodMetadata> resultMethods = new ArrayList<>(methods.size());
            for (MutableMethod method : methods) resultMethods.add(method.freeze());
            return new ClassMetadata(className, true, classAnnotations, resultMethods);
        }

        private void parseConstantPool() {
            int count = input.u2();
            if (count <= 0 || count > MAX_CONSTANT_POOL_ENTRIES) fail();
            constantPool = new Object[count];
            constantTags = new byte[count];
            for (int i = 1; i < count; i++) {
                int tag = input.u1();
                constantTags[i] = (byte) tag;
                switch (tag) {
                    case 1 -> {
                        int length = input.u2();
                        if (length > MAX_UTF8_BYTES) fail();
                        constantPool[i] = new String(input.bytes(length), StandardCharsets.UTF_8);
                    }
                    case 3, 4 -> {
                        constantPool[i] = input.u4();
                    }
                    case 5, 6 -> {
                        constantPool[i] = (input.u4() << 32) | input.u4();
                        if (++i >= count) fail();
                    }
                    case 7, 8, 16, 19, 20 -> constantPool[i] = input.u2();
                    case 9, 10, 11, 12, 17, 18 -> {
                        input.u2();
                        input.u2();
                    }
                    case 15 -> {
                        input.u1();
                        input.u2();
                    }
                    default -> fail();
                }
            }
        }

        private void skipMembers(Cursor cursor) {
            int count = bounded(cursor.u2(), MAX_MEMBERS);
            for (int i = 0; i < count; i++) {
                cursor.skip(6);
                parseAttributes(cursor, (name, body) -> { });
            }
        }

        private List<MutableMethod> parseMethods() {
            int count = bounded(input.u2(), MAX_MEMBERS);
            List<MutableMethod> methods = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                input.u2(); // access_flags
                MutableMethod method = new MutableMethod(utf(input.u2()), utf(input.u2()));
                int parameters = parameterCount(method.descriptor);
                if ((long) totalParameters + parameters > MAX_TOTAL_PARAMETERS) fail();
                totalParameters += parameters;
                method.ensureParameters(parameters);
                parseAttributes(input, (name, body) -> {
                    if (isAnnotationAttribute(name)) {
                        method.annotations.addAll(parseAnnotations(body));
                    } else if (name.equals("RuntimeVisibleParameterAnnotations")
                            || name.equals("RuntimeInvisibleParameterAnnotations")) {
                        parseParameterAnnotations(body, method);
                    } else if (name.equals("MethodParameters")) {
                        parseMethodParameters(body, method);
                    }
                });
                methods.add(method);
            }
            return methods;
        }

        private void parseAttributes(Cursor cursor, AttributeConsumer consumer) {
            int count = bounded(cursor.u2(), MAX_ATTRIBUTES);
            if ((long) totalAttributes + count > MAX_TOTAL_ATTRIBUTES) fail();
            totalAttributes += count;
            for (int i = 0; i < count; i++) {
                String name = utf(cursor.u2());
                long length = cursor.u4();
                Cursor body = cursor.slice(length);
                consumer.accept(name, body);
            }
        }

        private List<AnnotationMetadata> parseAnnotations(Cursor body) {
            int count = bounded(body.u2(), MAX_ANNOTATIONS);
            List<AnnotationMetadata> result = new ArrayList<>(count);
            for (int i = 0; i < count; i++) result.add(parseAnnotation(body, 0));
            if (body.remaining() != 0) fail();
            return result;
        }

        private AnnotationMetadata parseAnnotation(Cursor cursor, int depth) {
            if (depth > MAX_VALUE_DEPTH || ++totalAnnotations > MAX_TOTAL_ANNOTATIONS) fail();
            String typeName = descriptorToType(utf(cursor.u2()));
            int pairs = bounded(cursor.u2(), MAX_ANNOTATION_PAIRS);
            Map<String, List<String>> values = new LinkedHashMap<>();
            for (int i = 0; i < pairs; i++) {
                String name = utf(cursor.u2());
                values.put(name, parseElementValue(cursor, depth + 1));
            }
            return new AnnotationMetadata(typeName, values);
        }

        private List<String> parseElementValue(Cursor cursor, int depth) {
            if (depth > MAX_VALUE_DEPTH || ++totalValues > MAX_TOTAL_VALUES) fail();
            int tag = cursor.u1();
            return switch (tag) {
                case 's' -> List.of(limit(utf(cursor.u2())));
                case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z' -> {
                    int index = cursor.u2();
                    requireConstant(index);
                    yield List.of(limit(String.valueOf(constantPool[index])));
                }
                case 'e' -> {
                    cursor.u2(); // enum type descriptor
                    yield List.of(limit(utf(cursor.u2())));
                }
                case 'c' -> List.of(limit(descriptorToType(utf(cursor.u2()))));
                case '@' -> List.of(limit("@" + parseAnnotation(cursor, depth).typeName()));
                case '[' -> {
                    int count = bounded(cursor.u2(), MAX_ARRAY_VALUES);
                    List<String> values = new ArrayList<>();
                    for (int i = 0; i < count; i++) values.addAll(parseElementValue(cursor, depth + 1));
                    yield List.copyOf(values);
                }
                default -> throw new MalformedClassFile();
            };
        }

        private void parseParameterAnnotations(Cursor body, MutableMethod method) {
            int parameters = body.u1();
            if (parameters > method.parameterAnnotations.size()) fail();
            for (int parameter = 0; parameter < parameters; parameter++) {
                int count = bounded(body.u2(), MAX_ANNOTATIONS);
                for (int i = 0; i < count; i++) {
                    method.parameterAnnotations.get(parameter).add(parseAnnotation(body, 0));
                }
            }
            if (body.remaining() != 0) fail();
        }

        private void parseMethodParameters(Cursor body, MutableMethod method) {
            int count = body.u1();
            if (count > method.parameterAnnotations.size()) fail();
            for (int i = 0; i < count; i++) {
                int nameIndex = body.u2();
                body.u2(); // access_flags
                method.parameterNames.set(i, nameIndex == 0 ? null : limit(utf(nameIndex)));
            }
            if (body.remaining() != 0) fail();
        }

        private int parameterCount(String descriptor) {
            if (descriptor.isEmpty() || descriptor.charAt(0) != '(') fail();
            int count = 0;
            int position = 1;
            while (position < descriptor.length() && descriptor.charAt(position) != ')') {
                while (descriptor.charAt(position) == '[') position++;
                char type = descriptor.charAt(position++);
                if (type == 'L') {
                    position = descriptor.indexOf(';', position);
                    if (position < 0) fail();
                    position++;
                } else if ("BCDFIJSZ".indexOf(type) < 0) {
                    fail();
                }
                if (++count > 255) fail();
            }
            if (position >= descriptor.length() || descriptor.charAt(position) != ')') fail();
            return count;
        }

        private String className(int classIndex) {
            requireTag(classIndex, 7);
            return limit(utf((Integer) constantPool[classIndex]).replace('/', '.'));
        }

        private String utf(int index) {
            requireTag(index, 1);
            return (String) constantPool[index];
        }

        private void requireTag(int index, int tag) {
            if (index <= 0 || index >= constantTags.length || constantTags[index] != tag) fail();
        }

        private void requireConstant(int index) {
            if (index <= 0 || index >= constantTags.length || constantTags[index] == 0) fail();
        }

        private static boolean isAnnotationAttribute(String name) {
            return name.equals("RuntimeVisibleAnnotations") || name.equals("RuntimeInvisibleAnnotations");
        }

        private static String descriptorToType(String descriptor) {
            if (descriptor.length() >= 2 && descriptor.charAt(0) == 'L'
                    && descriptor.charAt(descriptor.length() - 1) == ';') {
                return descriptor.substring(1, descriptor.length() - 1).replace('/', '.');
            }
            return limit(descriptor);
        }

        private static int bounded(int value, int maximum) {
            if (value < 0 || value > maximum) fail();
            return value;
        }

        private static String limit(String value) {
            if (value == null) return "";
            StringBuilder safe = new StringBuilder(Math.min(value.length(), MAX_VALUE_LENGTH));
            for (int i = 0; i < value.length() && safe.length() < MAX_VALUE_LENGTH; i++) {
                char c = value.charAt(i);
                safe.append(Character.isISOControl(c) ? '?' : c);
            }
            return safe.toString();
        }
    }

    @FunctionalInterface
    private interface AttributeConsumer {
        void accept(String name, Cursor body);
    }

    private static final class MutableMethod {
        private final String name;
        private final String descriptor;
        private final List<AnnotationMetadata> annotations = new ArrayList<>();
        private final List<List<AnnotationMetadata>> parameterAnnotations = new ArrayList<>();
        private final List<String> parameterNames = new ArrayList<>();

        private MutableMethod(String name, String descriptor) {
            this.name = name;
            this.descriptor = descriptor;
        }

        private void ensureParameters(int count) {
            while (parameterAnnotations.size() < count) parameterAnnotations.add(new ArrayList<>());
            while (parameterNames.size() < count) parameterNames.add(null);
        }

        private MethodMetadata freeze() {
            List<ParameterMetadata> parameters = new ArrayList<>(parameterAnnotations.size());
            for (int i = 0; i < parameterAnnotations.size(); i++) {
                parameters.add(new ParameterMetadata(i, parameterNames.get(i), parameterAnnotations.get(i)));
            }
            return new MethodMetadata(name, descriptor, annotations, parameters);
        }
    }

    private static final class Cursor {
        private final byte[] bytes;
        private final int end;
        private int position;

        private Cursor(byte[] bytes, int start, int end) {
            this.bytes = bytes;
            this.position = start;
            this.end = end;
            if (start < 0 || end < start || end > bytes.length) fail();
        }

        private int u1() {
            require(1);
            return bytes[position++] & 0xff;
        }

        private int u2() {
            return (u1() << 8) | u1();
        }

        private long u4() {
            return ((long) u1() << 24) | ((long) u1() << 16) | ((long) u1() << 8) | u1();
        }

        private byte[] bytes(int count) {
            require(count);
            byte[] result = java.util.Arrays.copyOfRange(bytes, position, position + count);
            position += count;
            return result;
        }

        private void skip(long count) {
            if (count < 0 || count > Integer.MAX_VALUE) fail();
            require((int) count);
            position += (int) count;
        }

        private Cursor slice(long length) {
            if (length < 0 || length > Integer.MAX_VALUE) fail();
            require((int) length);
            Cursor result = new Cursor(bytes, position, position + (int) length);
            position += (int) length;
            return result;
        }

        private int remaining() {
            return end - position;
        }

        private void require(int count) {
            if (count < 0 || count > end - position) fail();
        }
    }

    private static void fail() {
        throw new MalformedClassFile();
    }

    private static final class MalformedClassFile extends RuntimeException { }
}
