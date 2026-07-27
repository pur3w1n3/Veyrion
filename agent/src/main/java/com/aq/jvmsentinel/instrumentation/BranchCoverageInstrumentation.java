package com.aq.jvmsentinel.instrumentation;

import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;

/**
 * Adds a compact hit probe immediately before every JVM conditional branch or switch instruction.
 *
 * <p>The branch index is local to the original method and follows bytecode visitation order. The
 * probe records that the branch site was reached; it does not claim which outgoing edge was taken.</p>
 */
final class BranchCoverageInstrumentation extends AsmVisitorWrapper.AbstractBase {
    private final String className;

    BranchCoverageInstrumentation(String className) {
        this.className = className;
    }

    @Override
    public ClassVisitor wrap(TypeDescription instrumentedType, ClassVisitor classVisitor,
                             Implementation.Context implementationContext, TypePool typePool,
                             FieldList<FieldDescription.InDefinedShape> fields,
                             MethodList<?> methods, int writerFlags, int readerFlags) {
        return new ClassVisitor(Opcodes.ASM9, classVisitor) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
                return new MethodVisitor(Opcodes.ASM9, delegate) {
                    private final String methodDescriptor = name + descriptor;
                    private int branchIndex;

                    @Override
                    public void visitJumpInsn(int opcode, net.bytebuddy.jar.asm.Label label) {
                        if (isConditionalJump(opcode)) {
                            emitHit(branchIndex++);
                        }
                        super.visitJumpInsn(opcode, label);
                    }

                    @Override
                    public void visitTableSwitchInsn(int minimum, int maximum,
                                                     net.bytebuddy.jar.asm.Label defaultLabel,
                                                     net.bytebuddy.jar.asm.Label... labels) {
                        emitHit(branchIndex++);
                        super.visitTableSwitchInsn(minimum, maximum, defaultLabel, labels);
                    }

                    @Override
                    public void visitLookupSwitchInsn(net.bytebuddy.jar.asm.Label defaultLabel,
                                                      int[] keys,
                                                      net.bytebuddy.jar.asm.Label[] labels) {
                        emitHit(branchIndex++);
                        super.visitLookupSwitchInsn(defaultLabel, keys, labels);
                    }

                    @Override
                    public void visitMaxs(int maxStack, int maxLocals) {
                        super.visitMaxs(maxStack + 3, maxLocals);
                    }

                    private void emitHit(int index) {
                        super.visitLdcInsn(className);
                        super.visitLdcInsn(methodDescriptor);
                        super.visitLdcInsn(index);
                        super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/aq/jvmsentinel/instrumentation/AgentRuntime",
                                "recordBranchHit",
                                "(Ljava/lang/String;Ljava/lang/String;I)V",
                                false);
                    }
                };
            }
        };
    }

    private static boolean isConditionalJump(int opcode) {
        return switch (opcode) {
            case Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE,
                    Opcodes.IFGT, Opcodes.IFLE,
                    Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT,
                    Opcodes.IF_ICMPGE, Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE,
                    Opcodes.IF_ACMPEQ, Opcodes.IF_ACMPNE,
                    Opcodes.IFNULL, Opcodes.IFNONNULL -> true;
            default -> false;
        };
    }
}
