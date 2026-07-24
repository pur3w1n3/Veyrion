package com.aq.jvmsentinel.control;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Small, dependency-free JSON codec used by the local control plane.
 *
 * <p>This is intentionally a strict subset of JSON (objects, arrays, strings,
 * booleans, null and finite numbers).  It is not used to parse arbitrary
 * artifact content; request bodies are bounded before they reach this class.
 * Keeping the codec here avoids adding a runtime dependency to the Java 17
 * metadata-only slice.</p>
 */
public final class JsonCodec {
    private JsonCodec() { }

    public static Object parse(String json) {
        if (json == null) throw new IllegalArgumentException("JSON body is required");
        Parser parser = new Parser(json);
        Object result = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) throw parser.error("trailing data");
        return result;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        Object value = parse(json);
        if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException("JSON object is required");
        for (Object key : map.keySet()) {
            if (!(key instanceof String)) throw new IllegalArgumentException("JSON object key is not a string");
        }
        return (Map<String, Object>) map;
    }

    public static String stringify(Object value) {
        StringBuilder out = new StringBuilder(256);
        write(value, out);
        return out.toString();
    }

    private static void write(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String text) {
            quote(text, out);
        } else if (value instanceof Character character) {
            quote(character.toString(), out);
        } else if (value instanceof Boolean || value instanceof Integer || value instanceof Long
                || value instanceof Short || value instanceof Byte) {
            out.append(value);
        } else if (value instanceof Number number) {
            double n = number.doubleValue();
            if (!Double.isFinite(n)) throw new IllegalArgumentException("JSON numbers must be finite");
            out.append(number);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) throw new IllegalArgumentException("JSON object key is not a string");
                if (!first) out.append(',');
                first = false;
                quote(key, out);
                out.append(':');
                write(entry.getValue(), out);
            }
            out.append('}');
        } else if (value instanceof Iterable<?> iterable) {
            out.append('[');
            boolean first = true;
            for (Object item : iterable) {
                if (!first) out.append(',');
                first = false;
                write(item, out);
            }
            out.append(']');
        } else if (value.getClass().isArray()) {
            out.append('[');
            int length = java.lang.reflect.Array.getLength(value);
            for (int i = 0; i < length; i++) {
                if (i > 0) out.append(',');
                write(java.lang.reflect.Array.get(value, i), out);
            }
            out.append(']');
        } else if (value instanceof Enum<?> enumeration) {
            quote(enumeration.name(), out);
        } else {
            throw new IllegalArgumentException("unsupported JSON value: " + value.getClass().getName());
        }
    }

    private static void quote(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static final class Parser {
        private final String input;
        private int position;
        private int depth;
        private static final int MAX_DEPTH = 64;

        private Parser(String input) { this.input = input; }

        private Object parseValue() {
            skipWhitespace();
            if (atEnd()) throw error("value is required");
            return switch (input.charAt(position)) {
                case '{' -> parseObjectValue();
                case '[' -> parseArrayValue();
                case '"' -> parseString();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default -> parseNumber();
            };
        }

        private Map<String, Object> parseObjectValue() {
            enterContainer();
            try {
                LinkedHashMap<String, Object> result = new LinkedHashMap<>();
                position++; // {
                skipWhitespace();
                if (consume('}')) return result;
                while (true) {
                    skipWhitespace();
                    if (atEnd() || input.charAt(position) != '"') throw error("object key must be a string");
                    String key = parseString();
                    if (result.containsKey(key)) throw error("duplicate object key");
                    skipWhitespace();
                    expect(':');
                    Object value = parseValue();
                    result.put(key, value);
                    skipWhitespace();
                    if (consume('}')) return result;
                    expect(',');
                }
            } finally {
                depth--;
            }
        }

        private List<Object> parseArrayValue() {
            enterContainer();
            try {
                ArrayList<Object> result = new ArrayList<>();
                position++; // [
                skipWhitespace();
                if (consume(']')) return result;
                while (true) {
                    result.add(parseValue());
                    skipWhitespace();
                    if (consume(']')) return result;
                    expect(',');
                }
            } finally {
                depth--;
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder result = new StringBuilder();
            while (!atEnd()) {
                char c = input.charAt(position++);
                if (c == '"') return result.toString();
                if (c < 0x20) throw error("control character in string");
                if (c != '\\') {
                    result.append(c);
                    continue;
                }
                if (atEnd()) throw error("unterminated escape");
                char escaped = input.charAt(position++);
                switch (escaped) {
                    case '"', '\\', '/' -> result.append(escaped);
                    case 'b' -> result.append('\b');
                    case 'f' -> result.append('\f');
                    case 'n' -> result.append('\n');
                    case 'r' -> result.append('\r');
                    case 't' -> result.append('\t');
                    case 'u' -> result.append(parseUnicodeEscape());
                    default -> throw error("invalid escape sequence");
                }
            }
            throw error("unterminated string");
        }

        private char parseUnicodeEscape() {
            if (position + 4 > input.length()) throw error("short unicode escape");
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(input.charAt(position++), 16);
                if (digit < 0) throw error("invalid unicode escape");
                value = value * 16 + digit;
            }
            return (char) value;
        }

        private Object parseLiteral(String literal, Object value) {
            if (!input.startsWith(literal, position)) throw error("invalid literal");
            position += literal.length();
            return value;
        }

        private Number parseNumber() {
            int start = position;
            if (consume('-')) { /* optional sign */ }
            if (atEnd()) throw error("invalid number");
            if (consume('0')) {
                if (!atEnd() && Character.isDigit(input.charAt(position))) throw error("leading zero in number");
            } else {
                if (atEnd() || !isDigitOneToNine(input.charAt(position))) throw error("invalid number");
                while (!atEnd() && Character.isDigit(input.charAt(position))) position++;
            }
            boolean decimal = false;
            if (consume('.')) {
                decimal = true;
                int digits = position;
                while (!atEnd() && Character.isDigit(input.charAt(position))) position++;
                if (digits == position) throw error("fraction digits are required");
            }
            if (!atEnd() && (input.charAt(position) == 'e' || input.charAt(position) == 'E')) {
                decimal = true;
                position++;
                if (!atEnd() && (input.charAt(position) == '+' || input.charAt(position) == '-')) position++;
                int digits = position;
                while (!atEnd() && Character.isDigit(input.charAt(position))) position++;
                if (digits == position) throw error("exponent digits are required");
            }
            String number = input.substring(start, position);
            try {
                if (!decimal) return Long.parseLong(number);
                double value = Double.parseDouble(number);
                if (!Double.isFinite(value)) throw error("number is not finite");
                return value;
            } catch (NumberFormatException exception) {
                throw error("invalid number");
            }
        }

        private void enterContainer() {
            if (++depth > MAX_DEPTH) throw error("JSON nesting is too deep");
        }

        private void skipWhitespace() {
            while (!atEnd() && Character.isWhitespace(input.charAt(position))) position++;
        }

        private boolean consume(char expected) {
            if (!atEnd() && input.charAt(position) == expected) {
                position++;
                return true;
            }
            return false;
        }

        private void expect(char expected) {
            if (!consume(expected)) throw error("expected '" + expected + "'");
        }

        private boolean atEnd() { return position >= input.length(); }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException(message + " at offset " + position);
        }

        private static boolean isDigitOneToNine(char value) { return value >= '1' && value <= '9'; }
    }
}
