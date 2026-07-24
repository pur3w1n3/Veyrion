package com.aq.jvmsentinel.analysis;

import com.aq.jvmsentinel.analysis.ClassMetadata.AnnotationMetadata;
import com.aq.jvmsentinel.analysis.ClassMetadata.MethodMetadata;
import com.aq.jvmsentinel.analysis.ClassMetadata.ParameterMetadata;
import com.aq.jvmsentinel.model.BytecodeFactIndex;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
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
    private static final int MAX_CODE_BYTES = 65_535;
    private static final int MAX_FACTS = 100_000;

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
        private int totalFacts;
        private String currentClassName;
        private final List<BytecodeFactIndex.FieldFact> fieldFacts = new ArrayList<>();
        private final List<BytecodeFactIndex.MethodFact> methodFacts = new ArrayList<>();
        private final List<BytecodeFactIndex.MemberAccessFact> memberAccessFacts = new ArrayList<>();
        private final List<BytecodeFactIndex.CallEdge> callEdges = new ArrayList<>();
        private final List<BytecodeFactIndex.UnresolvedDynamicFact> unresolvedDynamics = new ArrayList<>();

        private Parser(byte[] bytes) {
            input = new Cursor(bytes, 0, bytes.length);
        }

        private ClassMetadata parse() {
            if (input.u4() != 0xCAFEBABEL) fail();
            input.u2(); // minor
            int major = input.u2();
            if (major < 45 || major > 100) fail();
            parseConstantPool();
            int accessFlags = input.u2();
            int thisClass = input.u2();
            int superClass = input.u2();
            String className = className(thisClass);
            currentClassName = className;
            int interfaces = bounded(input.u2(), MAX_MEMBERS);
            List<String> interfaceNames = new ArrayList<>(interfaces);
            for (int i = 0; i < interfaces; i++) interfaceNames.add(className(input.u2()));
            parseFields(input);
            List<MutableMethod> methods = parseMethods();
            List<AnnotationMetadata> classAnnotations = new ArrayList<>();
            parseAttributes(input, (name, body) -> {
                if (isAnnotationAttribute(name)) classAnnotations.addAll(parseAnnotations(body));
            });
            if (input.remaining() != 0) fail();
            List<MethodMetadata> resultMethods = new ArrayList<>(methods.size());
            for (MutableMethod method : methods) resultMethods.add(method.freeze());
            String superName = superClass == 0 ? null : className(superClass);
            BytecodeFactIndex.ClassFact classFact = new BytecodeFactIndex.ClassFact(
                    className, superName, interfaceNames, accessFlags, "classfile:" + className);
            return new ClassMetadata(className, true, classAnnotations, resultMethods, classFact,
                    fieldFacts, methodFacts, memberAccessFacts, callEdges, unresolvedDynamics);
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
                        constantPool[i] = decodeModifiedUtf8(input.bytes(length));
                    }
                    case 3, 4 -> {
                        constantPool[i] = input.u4();
                    }
                    case 5, 6 -> {
                        constantPool[i] = (input.u4() << 32) | input.u4();
                        if (++i >= count) fail();
                    }
                    case 7, 8, 16, 19, 20 -> constantPool[i] = input.u2();
                    case 9, 10, 11, 12, 17, 18 ->
                            constantPool[i] = new CpPair(input.u2(), input.u2());
                    case 15 -> constantPool[i] = new CpPair(input.u1(), input.u2());
                    default -> fail();
                }
            }
        }

        private void parseFields(Cursor cursor) {
            int count = bounded(cursor.u2(), MAX_MEMBERS);
            for (int i = 0; i < count; i++) {
                int access = cursor.u2();
                String name = utf(cursor.u2());
                String descriptor = utf(cursor.u2());
                addFact();
                fieldFacts.add(new BytecodeFactIndex.FieldFact(currentClassName, name, descriptor, access,
                        "classfile:" + currentClassName + "#" + name + ":" + descriptor));
                parseAttributes(cursor, (attributeName, body) -> { });
            }
        }

        private List<MutableMethod> parseMethods() {
            int count = bounded(input.u2(), MAX_MEMBERS);
            List<MutableMethod> methods = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                int accessFlags = input.u2();
                MutableMethod method = new MutableMethod(utf(input.u2()), utf(input.u2()), accessFlags, i);
                addFact();
                methodFacts.add(new BytecodeFactIndex.MethodFact(currentClassName, method.name, method.descriptor,
                        accessFlags, "classfile:" + currentClassName + "#" + method.name + method.descriptor));
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
                    } else if (name.equals("Code")) {
                        parseCode(body, method);
                    }
                });
                if ((accessFlags & 0x0100) != 0) {
                    BytecodeFactIndex.InstructionEvidence location = new BytecodeFactIndex.InstructionEvidence(
                            currentClassName, method.name, method.descriptor, -1, method.methodOrdinal);
                    addFact();
                    unresolvedDynamics.add(new BytecodeFactIndex.UnresolvedDynamicFact(
                            "JNI", "native method implementation is outside the classfile", location));
                }
                methods.add(method);
            }
            return methods;
        }

        private void parseCode(Cursor body, MutableMethod method) {
            body.u2(); // max_stack
            body.u2(); // max_locals
            long declaredLength = body.u4();
            if (declaredLength > MAX_CODE_BYTES) fail();
            Cursor code = body.slice(declaredLength);
            scanInstructions(code, method);
            int exceptionHandlers = bounded(body.u2(), MAX_MEMBERS);
            body.skip((long) exceptionHandlers * 8);
            parseAttributes(body, (attributeName, nested) -> { });
            if (body.remaining() != 0) fail();
        }

        private void scanInstructions(Cursor code, MutableMethod method) {
            int ordinal = 0;
            while (code.remaining() > 0) {
                int offset = code.position();
                int opcode = code.u1();
                BytecodeFactIndex.InstructionEvidence location = new BytecodeFactIndex.InstructionEvidence(
                        currentClassName, method.name, method.descriptor, offset, ordinal++);
                switch (opcode) {
                    case 178, 179, 180, 181 -> {
                        int reference = code.u2();
                        addMemberAccess(opcode == 178 || opcode == 180
                                        ? BytecodeFactIndex.AccessKind.FIELD_READ
                                        : BytecodeFactIndex.AccessKind.FIELD_WRITE,
                                reference, location, false);
                    }
                    case 182, 183, 184 -> {
                        int reference = code.u2();
                        BytecodeFactIndex.AccessKind kind = opcode == 182
                                ? BytecodeFactIndex.AccessKind.INVOKE_VIRTUAL
                                : opcode == 183 ? BytecodeFactIndex.AccessKind.INVOKE_SPECIAL
                                : BytecodeFactIndex.AccessKind.INVOKE_STATIC;
                        addMemberAccess(kind, reference, location, true);
                    }
                    case 185 -> {
                        int reference = code.u2();
                        code.u1(); // argument count
                        if (code.u1() != 0) fail();
                        addMemberAccess(BytecodeFactIndex.AccessKind.INVOKE_INTERFACE,
                                reference, location, true);
                    }
                    case 186 -> {
                        int reference = code.u2();
                        if (code.u2() != 0) fail();
                        addInvokeDynamic(reference, location);
                    }
                    case 170 -> skipTableSwitch(code);
                    case 171 -> skipLookupSwitch(code);
                    case 196 -> skipWide(code);
                    default -> code.skip(fixedOperandLength(opcode));
                }
            }
        }

        private void addMemberAccess(BytecodeFactIndex.AccessKind kind, int reference,
                                     BytecodeFactIndex.InstructionEvidence location, boolean invocation) {
            MemberReference target = memberReference(reference);
            addFact();
            memberAccessFacts.add(new BytecodeFactIndex.MemberAccessFact(
                    kind, target.owner, target.name, target.descriptor, location));
            if (!invocation) return;
            BytecodeFactIndex.EdgeKind edgeKind =
                    kind == BytecodeFactIndex.AccessKind.INVOKE_STATIC
                            || kind == BytecodeFactIndex.AccessKind.INVOKE_SPECIAL
                            ? BytecodeFactIndex.EdgeKind.DIRECT
                            : BytecodeFactIndex.EdgeKind.CONSERVATIVE_CHA;
            String limitation = edgeKind == BytecodeFactIndex.EdgeKind.DIRECT
                    ? "symbolic direct target; class-path resolution not performed"
                    : "declared receiver target only; overrides and runtime receiver types are not resolved";
            addFact();
            callEdges.add(new BytecodeFactIndex.CallEdge(
                    currentClassName, location.methodName(), location.methodDescriptor(),
                    target.owner, target.name, target.descriptor, edgeKind, limitation, location));
            String mechanism = dynamicMechanism(target);
            if (mechanism != null) {
                addFact();
                unresolvedDynamics.add(new BytecodeFactIndex.UnresolvedDynamicFact(
                        mechanism, "runtime target introduced through " + target.owner + "#" + target.name, location));
            }
        }

        private void addInvokeDynamic(int reference, BytecodeFactIndex.InstructionEvidence location) {
            requireTag(reference, 18);
            CpPair dynamic = (CpPair) constantPool[reference];
            NameAndType target = nameAndType(dynamic.second);
            addFact();
            memberAccessFacts.add(new BytecodeFactIndex.MemberAccessFact(
                    BytecodeFactIndex.AccessKind.INVOKE_DYNAMIC, "<dynamic>",
                    target.name, target.descriptor, location));
            addFact();
            callEdges.add(new BytecodeFactIndex.CallEdge(
                    currentClassName, location.methodName(), location.methodDescriptor(),
                    "<dynamic>", target.name, target.descriptor, BytecodeFactIndex.EdgeKind.UNRESOLVED,
                    "invokedynamic bootstrap and runtime target are not executed or resolved", location));
            addFact();
            unresolvedDynamics.add(new BytecodeFactIndex.UnresolvedDynamicFact(
                    "INVOKEDYNAMIC", "bootstrap method index=" + dynamic.first, location));
        }

        private MemberReference memberReference(int index) {
            if (index <= 0 || index >= constantTags.length
                    || (constantTags[index] != 9 && constantTags[index] != 10 && constantTags[index] != 11)) fail();
            CpPair reference = (CpPair) constantPool[index];
            NameAndType nameAndType = nameAndType(reference.second);
            return new MemberReference(className(reference.first), nameAndType.name, nameAndType.descriptor);
        }

        private NameAndType nameAndType(int index) {
            requireTag(index, 12);
            CpPair pair = (CpPair) constantPool[index];
            return new NameAndType(utf(pair.first), utf(pair.second));
        }

        private static String dynamicMechanism(MemberReference target) {
            if (target.owner.equals("java.lang.reflect.Proxy") && target.name.equals("newProxyInstance")) {
                return "DYNAMIC_PROXY";
            }
            if (target.owner.startsWith("java.lang.reflect.")
                    || target.owner.equals("java.lang.Class") && (target.name.equals("forName")
                    || target.name.equals("newInstance") || target.name.startsWith("getDeclared")
                    || target.name.startsWith("getMethod") || target.name.startsWith("getConstructor"))
                    || target.owner.startsWith("java.lang.invoke.MethodHandle")
                    || target.owner.equals("java.lang.invoke.MethodHandles$Lookup")) {
                return "REFLECTION";
            }
            if (target.owner.equals("java.lang.System")
                    && (target.name.equals("load") || target.name.equals("loadLibrary"))) {
                return "JNI";
            }
            return null;
        }

        private static void skipWide(Cursor code) {
            int modified = code.u1();
            if (modified == 132) {
                code.skip(4);
            } else if (modified >= 21 && modified <= 25
                    || modified >= 54 && modified <= 58 || modified == 169) {
                code.skip(2);
            } else {
                fail();
            }
        }

        private static void skipTableSwitch(Cursor code) {
            skipSwitchPadding(code);
            code.s4(); // default
            long low = code.s4();
            long high = code.s4();
            if (high < low || high - low + 1 > Integer.MAX_VALUE) fail();
            code.skip((high - low + 1) * 4);
        }

        private static void skipLookupSwitch(Cursor code) {
            skipSwitchPadding(code);
            code.s4(); // default
            long pairs = code.s4();
            if (pairs < 0) fail();
            if (pairs > Integer.MAX_VALUE / 8) fail();
            code.skip(pairs * 8);
        }

        private static void skipSwitchPadding(Cursor code) {
            while (code.position() % 4 != 0) code.u1();
        }

        private static int fixedOperandLength(int opcode) {
            return switch (opcode) {
                case 16, 18, 21, 22, 23, 24, 25, 54, 55, 56, 57, 58, 169, 188 -> 1;
                case 17, 19, 20, 132,
                        153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
                        165, 166, 167, 168, 187, 189, 192, 193, 198, 199 -> 2;
                case 197 -> 3;
                case 200, 201 -> 4;
                default -> {
                    if (opcode < 0 || opcode > 201) fail();
                    yield 0;
                }
            };
        }

        private void addFact() {
            if (++totalFacts > MAX_FACTS) fail();
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

        private static String decodeModifiedUtf8(byte[] value) {
            byte[] encoded = new byte[value.length + 2];
            encoded[0] = (byte) (value.length >>> 8);
            encoded[1] = (byte) value.length;
            System.arraycopy(value, 0, encoded, 2, value.length);
            try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
                return input.readUTF();
            } catch (IOException malformed) {
                fail();
                return "";
            }
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
        private final int accessFlags;
        private final int methodOrdinal;
        private final List<AnnotationMetadata> annotations = new ArrayList<>();
        private final List<List<AnnotationMetadata>> parameterAnnotations = new ArrayList<>();
        private final List<String> parameterNames = new ArrayList<>();

        private MutableMethod(String name, String descriptor, int accessFlags, int methodOrdinal) {
            this.name = name;
            this.descriptor = descriptor;
            this.accessFlags = accessFlags;
            this.methodOrdinal = methodOrdinal;
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
            return new MethodMetadata(name, descriptor, accessFlags, annotations, parameters);
        }
    }

    private static final class Cursor {
        private final byte[] bytes;
        private final int start;
        private final int end;
        private int position;

        private Cursor(byte[] bytes, int start, int end) {
            this.bytes = bytes;
            this.start = start;
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

        private int s4() {
            return (int) u4();
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

        private int position() {
            return position - start;
        }

        private void require(int count) {
            if (count < 0 || count > end - position) fail();
        }
    }

    private record CpPair(int first, int second) { }
    private record NameAndType(String name, String descriptor) { }
    private record MemberReference(String owner, String name, String descriptor) { }

    private static void fail() {
        throw new MalformedClassFile();
    }

    private static final class MalformedClassFile extends RuntimeException { }
}
