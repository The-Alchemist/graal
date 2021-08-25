/*
 * Copyright (c) 2015, 2017, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.oracle.svm.core.code;

import static com.oracle.svm.core.util.VMError.shouldNotReachHere;

import java.lang.annotation.Annotation;
// Checkstyle: stop
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
// Checkstyle: resume
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.graalvm.compiler.code.CompilationResult;
import org.graalvm.compiler.core.common.NumUtil;
import org.graalvm.compiler.core.common.util.FrequencyEncoder;
import org.graalvm.compiler.core.common.util.TypeConversion;
import org.graalvm.compiler.core.common.util.UnsafeArrayTypeWriter;
import org.graalvm.compiler.options.Option;
import org.graalvm.nativeimage.ImageSingletons;
import org.graalvm.nativeimage.impl.RuntimeReflectionSupport;
import org.graalvm.util.GuardedAnnotationAccess;
import org.graalvm.word.Pointer;
import org.graalvm.word.UnsignedWord;
import org.graalvm.word.WordFactory;

import com.oracle.svm.core.CalleeSavedRegisters;
import com.oracle.svm.core.ReservedRegisters;
import com.oracle.svm.core.SubstrateOptions;
import com.oracle.svm.core.annotate.Uninterruptible;
import com.oracle.svm.core.c.NonmovableArray;
import com.oracle.svm.core.c.NonmovableArrays;
import com.oracle.svm.core.c.NonmovableObjectArray;
import com.oracle.svm.core.code.FrameInfoQueryResult.ValueInfo;
import com.oracle.svm.core.code.FrameInfoQueryResult.ValueType;
import com.oracle.svm.core.config.ConfigurationValues;
import com.oracle.svm.core.config.ObjectLayout;
import com.oracle.svm.core.deopt.DeoptEntryInfopoint;
import com.oracle.svm.core.heap.CodeReferenceMapDecoder;
import com.oracle.svm.core.heap.CodeReferenceMapEncoder;
import com.oracle.svm.core.heap.ObjectReferenceVisitor;
import com.oracle.svm.core.heap.ReferenceMapEncoder;
import com.oracle.svm.core.heap.SubstrateReferenceMap;
import com.oracle.svm.core.hub.DynamicHub;
import com.oracle.svm.core.hub.LayoutEncoding;
import com.oracle.svm.core.meta.SharedField;
import com.oracle.svm.core.meta.SharedMethod;
import com.oracle.svm.core.meta.SharedType;
import com.oracle.svm.core.meta.SubstrateObjectConstant;
import com.oracle.svm.core.option.HostedOptionKey;
import com.oracle.svm.core.util.ByteArrayReader;
import com.oracle.svm.core.util.Counter;
import com.oracle.svm.core.util.VMError;

import jdk.vm.ci.code.BytecodeFrame;
import jdk.vm.ci.code.DebugInfo;
import jdk.vm.ci.code.RegisterValue;
import jdk.vm.ci.code.StackLockValue;
import jdk.vm.ci.code.StackSlot;
import jdk.vm.ci.code.ValueUtil;
import jdk.vm.ci.code.VirtualObject;
import jdk.vm.ci.code.site.Call;
import jdk.vm.ci.code.site.ExceptionHandler;
import jdk.vm.ci.code.site.Infopoint;
import jdk.vm.ci.meta.JavaConstant;
import jdk.vm.ci.meta.JavaKind;
import jdk.vm.ci.meta.JavaValue;
// Checkstyle: stop
import sun.invoke.util.Wrapper;
import sun.reflect.annotation.AnnotationType;
// Checkstyle: resume

public class CodeInfoEncoder {

    public static class Options {
        @Option(help = "Statistics about code and deoptimization information") //
        public static final HostedOptionKey<Boolean> CodeInfoEncoderCounters = new HostedOptionKey<>(false);
    }

    public static class Counters {
        public final Counter.Group group = new Counter.Group(Options.CodeInfoEncoderCounters, "CodeInfoEncoder");
        final Counter methodCount = new Counter(group, "Number of methods", "Number of methods encoded");
        final Counter codeSize = new Counter(group, "Code size", "Total size of machine code");
        final Counter frameInfoSize = new Counter(group, "Frame info size", "Total size of encoded frame information");
        final Counter frameCount = new Counter(group, "Number of frames", "Number of frames encoded");
        final Counter stackValueCount = new Counter(group, "Number of stack values", "Number of stack values encoded");
        final Counter registerValueCount = new Counter(group, "Number of register values", "Number of register values encoded");
        final Counter constantValueCount = new Counter(group, "Number of constant values", "Number of constant values encoded");
        final Counter virtualObjectsCount = new Counter(group, "Number of virtual objects", "Number of virtual objects encoded");
    }

    public static final class Encoders {
        final FrequencyEncoder<JavaConstant> objectConstants;
        final FrequencyEncoder<Class<?>> sourceClasses;
        final FrequencyEncoder<String> sourceMethodNames;
        final FrequencyEncoder<String> names;

        private Encoders() {
            this.objectConstants = FrequencyEncoder.createEqualityEncoder();
            this.sourceClasses = FrequencyEncoder.createEqualityEncoder();
            this.sourceMethodNames = FrequencyEncoder.createEqualityEncoder();
            sourceMethodNames.addObject("<init>");
            if (FrameInfoDecoder.encodeDebugNames() || FrameInfoDecoder.encodeSourceReferences()) {
                this.names = FrequencyEncoder.createEqualityEncoder();
            } else {
                this.names = null;
            }
        }

        private void encodeAllAndInstall(CodeInfo target, ReferenceAdjuster adjuster) {
            JavaConstant[] encodedJavaConstants = objectConstants.encodeAll(new JavaConstant[objectConstants.getLength()]);
            Class<?>[] sourceClassesArray = null;
            String[] sourceMethodNamesArray = null;
            String[] namesArray = null;
            final boolean encodeDebugNames = FrameInfoDecoder.encodeDebugNames();
            if (encodeDebugNames || FrameInfoDecoder.encodeSourceReferences()) {
                sourceClassesArray = sourceClasses.encodeAll(new Class<?>[sourceClasses.getLength()]);
                sourceMethodNamesArray = sourceMethodNames.encodeAll(new String[sourceMethodNames.getLength()]);
            }
            if (encodeDebugNames) {
                namesArray = names.encodeAll(new String[names.getLength()]);
            }
            install(target, encodedJavaConstants, sourceClassesArray, sourceMethodNamesArray, namesArray, adjuster);
        }

        @Uninterruptible(reason = "Nonmovable object arrays are not visible to GC until installed in target.")
        private static void install(CodeInfo target, JavaConstant[] objectConstantsArray, Class<?>[] sourceClassesArray,
                        String[] sourceMethodNamesArray, String[] namesArray, ReferenceAdjuster adjuster) {

            NonmovableObjectArray<Object> frameInfoObjectConstants = adjuster.copyOfObjectConstantArray(objectConstantsArray);
            NonmovableObjectArray<Class<?>> frameInfoSourceClasses = (sourceClassesArray != null) ? adjuster.copyOfObjectArray(sourceClassesArray) : NonmovableArrays.nullArray();
            NonmovableObjectArray<String> frameInfoSourceMethodNames = (sourceMethodNamesArray != null) ? adjuster.copyOfObjectArray(sourceMethodNamesArray) : NonmovableArrays.nullArray();
            NonmovableObjectArray<String> frameInfoNames = (namesArray != null) ? adjuster.copyOfObjectArray(namesArray) : NonmovableArrays.nullArray();

            CodeInfoAccess.setEncodings(target, frameInfoObjectConstants, frameInfoSourceClasses, frameInfoSourceMethodNames, frameInfoNames);
        }
    }

    static class IPData {
        protected long ip;
        protected int frameSizeEncoding;
        protected int exceptionOffset;
        protected ReferenceMapEncoder.Input referenceMap;
        protected long referenceMapIndex;
        protected FrameInfoEncoder.FrameData frameData;
        protected IPData next;
    }

    private final TreeMap<Long, IPData> entries;
    private final Encoders encoders;
    private final FrameInfoEncoder frameInfoEncoder;
    private final TreeMap<SharedType, Set<Executable>> methodData;
    private final AnnotationEncoder annotationEncoder;

    private NonmovableArray<Byte> codeInfoIndex;
    private NonmovableArray<Byte> codeInfoEncodings;
    private NonmovableArray<Byte> referenceMapEncoding;
    private NonmovableArray<Byte> methodDataEncoding;
    private NonmovableArray<Byte> methodDataIndexEncoding;

    public CodeInfoEncoder(FrameInfoEncoder.Customization frameInfoCustomization) {
        this.entries = new TreeMap<>();
        this.encoders = new Encoders();
        this.frameInfoEncoder = new FrameInfoEncoder(frameInfoCustomization, encoders);
        this.methodData = new TreeMap<>(Comparator.comparingLong(t -> t.getHub().getTypeID()));
        this.annotationEncoder = new AnnotationEncoder();
    }

    public static int getEntryOffset(Infopoint infopoint) {
        if (infopoint instanceof Call || infopoint instanceof DeoptEntryInfopoint) {
            int offset = infopoint.pcOffset;
            if (infopoint instanceof Call) {
                // add size of the Call instruction to get the PCEntry
                offset += ((Call) infopoint).size;
            }
            return offset;
        }
        return -1;
    }

    @SuppressWarnings("unchecked")
    public void addClass(Class<?> clazz) {
        encoders.sourceClasses.addObject(clazz);
        if (clazz.isAnnotation()) {
            for (String valueName : AnnotationType.getInstance((Class<? extends Annotation>) clazz).members().keySet()) {
                encoders.sourceMethodNames.addObject(valueName);
            }
        }
    }

    public void addMethod(SharedMethod method, CompilationResult compilation, int compilationOffset) {
        int totalFrameSize = compilation.getTotalFrameSize();
        boolean isEntryPoint = method.isEntryPoint();
        boolean hasCalleeSavedRegisters = method.hasCalleeSavedRegisters();

        /* Mark the method start and register the frame size. */
        IPData startEntry = makeEntry(compilationOffset);
        startEntry.frameSizeEncoding = encodeFrameSize(totalFrameSize, true, isEntryPoint, hasCalleeSavedRegisters);

        /* Register the frame size for all entries that are starting points for the index. */
        long entryIP = CodeInfoDecoder.lookupEntryIP(CodeInfoDecoder.indexGranularity() + compilationOffset);
        while (entryIP <= CodeInfoDecoder.lookupEntryIP(compilation.getTargetCodeSize() + compilationOffset - 1)) {
            IPData entry = makeEntry(entryIP);
            entry.frameSizeEncoding = encodeFrameSize(totalFrameSize, false, isEntryPoint, hasCalleeSavedRegisters);
            entryIP += CodeInfoDecoder.indexGranularity();
        }

        /* Make entries for all calls and deoptimization entry points of the method. */
        for (Infopoint infopoint : compilation.getInfopoints()) {
            final DebugInfo debugInfo = infopoint.debugInfo;
            if (debugInfo != null) {
                final int offset = getEntryOffset(infopoint);
                if (offset >= 0) {
                    IPData entry = makeEntry(offset + compilationOffset);
                    assert entry.referenceMap == null && entry.frameData == null;
                    entry.referenceMap = (ReferenceMapEncoder.Input) debugInfo.getReferenceMap();
                    entry.frameData = frameInfoEncoder.addDebugInfo(method, infopoint, totalFrameSize);
                }
            }
        }

        /* Make entries for all exception handlers. */
        for (ExceptionHandler handler : compilation.getExceptionHandlers()) {
            final IPData entry = makeEntry(handler.pcOffset + compilationOffset);
            assert entry.exceptionOffset == 0;
            entry.exceptionOffset = handler.handlerPos - handler.pcOffset;
        }

        ImageSingletons.lookup(Counters.class).methodCount.inc();
        ImageSingletons.lookup(Counters.class).codeSize.add(compilation.getTargetCodeSize());
    }

    public void registerMethod(SharedMethod method, Executable reflectMethod) {
        if (reflectMethod != null && shouldIncludeMethod(reflectMethod)) {
            if (reflectMethod instanceof Method) {
                encoders.sourceMethodNames.addObject(reflectMethod.getName());
            }
            /* Register string values in annotations */
            annotationEncoder.registerStrings(GuardedAnnotationAccess.getDeclaredAnnotations(reflectMethod));
            for (Annotation[] annotations : reflectMethod.getParameterAnnotations()) {
                annotationEncoder.registerStrings(annotations);
            }
            SharedType declaringType = (SharedType) method.getDeclaringClass();
            methodData.computeIfAbsent(declaringType, t -> new HashSet<>()).add(reflectMethod);
        }
    }

    private static boolean shouldIncludeMethod(Executable reflectMethod) {
        return !SubstrateOptions.ConfigureReflectionMetadata.getValue() || ImageSingletons.lookup(RuntimeReflectionSupport.class).isQueried(reflectMethod);
    }

    private IPData makeEntry(long ip) {
        IPData result = entries.get(ip);
        if (result == null) {
            result = new IPData();
            result.ip = ip;
            entries.put(ip, result);
        }
        return result;
    }

    public void encodeAllAndInstall(CodeInfo target, ReferenceAdjuster adjuster) {
        encoders.encodeAllAndInstall(target, adjuster);
        encodeReferenceMaps();
        frameInfoEncoder.encodeAllAndInstall(target);
        encodeMethodMetadata();
        encodeIPData();

        install(target);
    }

    private void install(CodeInfo target) {
        CodeInfoAccess.setCodeInfo(target, codeInfoIndex, codeInfoEncodings, referenceMapEncoding, methodDataEncoding, methodDataIndexEncoding);
    }

    private void encodeReferenceMaps() {
        CodeReferenceMapEncoder referenceMapEncoder = new CodeReferenceMapEncoder();
        for (IPData data : entries.values()) {
            referenceMapEncoder.add(data.referenceMap);
        }
        referenceMapEncoding = referenceMapEncoder.encodeAll();
        for (IPData data : entries.values()) {
            data.referenceMapIndex = referenceMapEncoder.lookupEncoding(data.referenceMap);
        }
    }

    public static final int NO_METHOD_METADATA = -1;

    private void encodeMethodMetadata() {
        UnsafeArrayTypeWriter dataEncodingBuffer = UnsafeArrayTypeWriter.create(ByteArrayReader.supportsUnalignedMemoryAccess());
        UnsafeArrayTypeWriter indexEncodingBuffer = UnsafeArrayTypeWriter.create(ByteArrayReader.supportsUnalignedMemoryAccess());
        long lastTypeID = -1;
        for (Map.Entry<SharedType, Set<Executable>> entry : methodData.entrySet()) {
            SharedType declaringType = entry.getKey();
            Set<Executable> methods = entry.getValue();
            long typeID = declaringType.getHub().getTypeID();
            assert typeID > lastTypeID;
            lastTypeID++;
            while (lastTypeID < typeID) {
                indexEncodingBuffer.putS4(NO_METHOD_METADATA);
                lastTypeID++;
            }
            long index = dataEncodingBuffer.getBytesWritten();
            indexEncodingBuffer.putU4(index);
            dataEncodingBuffer.putUV(methods.size());
            for (Executable method : methods) {
                String name = method instanceof Constructor<?> ? "<init>" : ((Method) method).getName();
                final int nameIndex = encoders.sourceMethodNames.getIndex(name);
                dataEncodingBuffer.putSV(nameIndex);

                dataEncodingBuffer.putUV(method.getModifiers());

                Class<?>[] parameterTypes = method.getParameterTypes();
                dataEncodingBuffer.putUV(parameterTypes.length);
                for (Class<?> parameterType : parameterTypes) {
                    final int paramClassIndex = encoders.sourceClasses.getIndex(encoders.sourceClasses.contains(parameterType) ? parameterType : Object.class);
                    dataEncodingBuffer.putSV(paramClassIndex);
                }

                Class<?> returnType = method instanceof Constructor<?> ? void.class : ((Method) method).getReturnType();
                final int returnTypeIndex = encoders.sourceClasses.getIndex(encoders.sourceClasses.contains(returnType) ? returnType : Object.class);
                dataEncodingBuffer.putSV(returnTypeIndex);

                Class<?>[] exceptionTypes = filterTypes(method.getExceptionTypes());
                dataEncodingBuffer.putUV(exceptionTypes.length);
                for (Class<?> exceptionClazz : exceptionTypes) {
                    final int exceptionClassIndex = encoders.sourceClasses.getIndex(exceptionClazz);
                    dataEncodingBuffer.putSV(exceptionClassIndex);
                }

                try {
                    byte[] annotations = annotationEncoder.encodeAnnotations(GuardedAnnotationAccess.getDeclaredAnnotations(method));
                    dataEncodingBuffer.putUV(annotations.length);
                    for (byte b : annotations) {
                        dataEncodingBuffer.putS1(b);
                    }
                    byte[] parameterAnnotations = annotationEncoder.encodeParameterAnnotations(method.getParameterAnnotations());
                    dataEncodingBuffer.putUV(parameterAnnotations.length);
                    for (byte b : parameterAnnotations) {
                        dataEncodingBuffer.putS1(b);
                    }
                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw shouldNotReachHere();
                }
            }
        }
        methodDataEncoding = NonmovableArrays.createByteArray(TypeConversion.asS4(dataEncodingBuffer.getBytesWritten()));
        dataEncodingBuffer.toByteBuffer(NonmovableArrays.asByteBuffer(methodDataEncoding));
        methodDataIndexEncoding = NonmovableArrays.createByteArray(TypeConversion.asS4(indexEncodingBuffer.getBytesWritten()));
        indexEncodingBuffer.toByteBuffer(NonmovableArrays.asByteBuffer(methodDataIndexEncoding));
    }

    private Class<?>[] filterTypes(Class<?>[] types) {
        List<Class<?>> filteredTypes = new ArrayList<>();
        for (Class<?> type : types) {
            if (encoders.sourceClasses.contains(type)) {
                filteredTypes.add(type);
            }
        }
        return filteredTypes.toArray(new Class<?>[0]);
    }

    /**
     * Inverse of {@link CodeInfoDecoder#decodeTotalFrameSize} and
     * {@link CodeInfoDecoder#decodeMethodStart}.
     */
    protected int encodeFrameSize(int totalFrameSize, boolean methodStart, boolean isEntryPoint, boolean hasCalleeSavedRegisters) {
        VMError.guarantee((totalFrameSize & CodeInfoDecoder.FRAME_SIZE_STATUS_MASK) == 0, "Frame size must be aligned");

        return totalFrameSize |
                        (methodStart ? CodeInfoDecoder.FRAME_SIZE_METHOD_START : 0) |
                        (isEntryPoint ? CodeInfoDecoder.FRAME_SIZE_ENTRY_POINT : 0) |
                        (hasCalleeSavedRegisters ? CodeInfoDecoder.FRAME_SIZE_HAS_CALLEE_SAVED_REGISTERS : 0);
    }

    private void encodeIPData() {
        IPData first = null;
        IPData prev = null;
        for (IPData cur : entries.values()) {
            if (first == null) {
                first = cur;
            } else {
                while (!TypeConversion.isU1(cur.ip - prev.ip)) {
                    final IPData filler = new IPData();
                    filler.ip = prev.ip + 0xFF;
                    prev.next = filler;
                    prev = filler;
                }
                prev.next = cur;
            }
            prev = cur;
        }

        long nextIndexIP = 0;
        UnsafeArrayTypeWriter indexBuffer = UnsafeArrayTypeWriter.create(ByteArrayReader.supportsUnalignedMemoryAccess());
        UnsafeArrayTypeWriter encodingBuffer = UnsafeArrayTypeWriter.create(ByteArrayReader.supportsUnalignedMemoryAccess());
        for (IPData data = first; data != null; data = data.next) {
            assert data.ip <= nextIndexIP;
            if (data.ip == nextIndexIP) {
                indexBuffer.putU4(encodingBuffer.getBytesWritten());
                nextIndexIP += CodeInfoDecoder.indexGranularity();
            }

            int entryFlags = 0;
            entryFlags = entryFlags | flagsForSizeEncoding(data) << CodeInfoDecoder.FS_SHIFT;
            entryFlags = entryFlags | flagsForExceptionOffset(data) << CodeInfoDecoder.EX_SHIFT;
            entryFlags = entryFlags | flagsForReferenceMapIndex(data) << CodeInfoDecoder.RM_SHIFT;
            entryFlags = entryFlags | flagsForDeoptFrameInfo(data) << CodeInfoDecoder.FI_SHIFT;

            encodingBuffer.putU1(entryFlags);
            encodingBuffer.putU1(data.next == null ? CodeInfoDecoder.DELTA_END_OF_TABLE : (data.next.ip - data.ip));

            writeSizeEncoding(encodingBuffer, data, entryFlags);
            writeExceptionOffset(encodingBuffer, data, entryFlags);
            writeReferenceMapIndex(encodingBuffer, data, entryFlags);
            writeDeoptFrameInfo(encodingBuffer, data, entryFlags);
        }

        codeInfoIndex = NonmovableArrays.createByteArray(TypeConversion.asU4(indexBuffer.getBytesWritten()));
        indexBuffer.toByteBuffer(NonmovableArrays.asByteBuffer(codeInfoIndex));
        codeInfoEncodings = NonmovableArrays.createByteArray(TypeConversion.asU4(encodingBuffer.getBytesWritten()));
        encodingBuffer.toByteBuffer(NonmovableArrays.asByteBuffer(codeInfoEncodings));
    }

    /**
     * Inverse of {@link CodeInfoDecoder#updateSizeEncoding}.
     */
    private static int flagsForSizeEncoding(IPData data) {
        if (data.frameSizeEncoding == 0) {
            return CodeInfoDecoder.FS_NO_CHANGE;
        } else if (TypeConversion.isS1(data.frameSizeEncoding)) {
            return CodeInfoDecoder.FS_SIZE_S1;
        } else if (TypeConversion.isS2(data.frameSizeEncoding)) {
            return CodeInfoDecoder.FS_SIZE_S2;
        } else if (TypeConversion.isS4(data.frameSizeEncoding)) {
            return CodeInfoDecoder.FS_SIZE_S4;
        } else {
            throw new IllegalArgumentException();
        }
    }

    private static void writeSizeEncoding(UnsafeArrayTypeWriter writeBuffer, IPData data, int entryFlags) {
        switch (CodeInfoDecoder.extractFS(entryFlags)) {
            case CodeInfoDecoder.FS_SIZE_S1:
                writeBuffer.putS1(data.frameSizeEncoding);
                break;
            case CodeInfoDecoder.FS_SIZE_S2:
                writeBuffer.putS2(data.frameSizeEncoding);
                break;
            case CodeInfoDecoder.FS_SIZE_S4:
                writeBuffer.putS4(data.frameSizeEncoding);
                break;
        }
    }

    /**
     * Inverse of {@link CodeInfoDecoder#loadExceptionOffset}.
     */
    private static int flagsForExceptionOffset(IPData data) {
        if (data.exceptionOffset == 0) {
            return CodeInfoDecoder.EX_NO_HANDLER;
        } else if (TypeConversion.isS1(data.exceptionOffset)) {
            return CodeInfoDecoder.EX_OFFSET_S1;
        } else if (TypeConversion.isS2(data.exceptionOffset)) {
            return CodeInfoDecoder.EX_OFFSET_S2;
        } else if (TypeConversion.isS4(data.exceptionOffset)) {
            return CodeInfoDecoder.EX_OFFSET_S4;
        } else {
            throw new IllegalArgumentException();
        }
    }

    private static void writeExceptionOffset(UnsafeArrayTypeWriter writeBuffer, IPData data, int entryFlags) {
        switch (CodeInfoDecoder.extractEX(entryFlags)) {
            case CodeInfoDecoder.EX_OFFSET_S1:
                writeBuffer.putS1(data.exceptionOffset);
                break;
            case CodeInfoDecoder.EX_OFFSET_S2:
                writeBuffer.putS2(data.exceptionOffset);
                break;
            case CodeInfoDecoder.EX_OFFSET_S4:
                writeBuffer.putS4(data.exceptionOffset);
                break;
        }
    }

    /**
     * Inverse of {@link CodeInfoDecoder#loadReferenceMapIndex}.
     */
    private static int flagsForReferenceMapIndex(IPData data) {
        if (data.referenceMap == null) {
            return CodeInfoDecoder.RM_NO_MAP;
        } else if (data.referenceMap.isEmpty()) {
            return CodeInfoDecoder.RM_EMPTY_MAP;
        } else if (TypeConversion.isU2(data.referenceMapIndex)) {
            return CodeInfoDecoder.RM_INDEX_U2;
        } else if (TypeConversion.isU4(data.referenceMapIndex)) {
            return CodeInfoDecoder.RM_INDEX_U4;
        } else {
            throw new IllegalArgumentException();
        }
    }

    private static void writeReferenceMapIndex(UnsafeArrayTypeWriter writeBuffer, IPData data, int entryFlags) {
        switch (CodeInfoDecoder.extractRM(entryFlags)) {
            case CodeInfoDecoder.RM_INDEX_U2:
                writeBuffer.putU2(data.referenceMapIndex);
                break;
            case CodeInfoDecoder.RM_INDEX_U4:
                writeBuffer.putU4(data.referenceMapIndex);
                break;
        }
    }

    /**
     * Inverse of {@link CodeInfoDecoder#loadFrameInfo}.
     */
    private static int flagsForDeoptFrameInfo(IPData data) {
        if (data.frameData == null) {
            return CodeInfoDecoder.FI_NO_DEOPT;
        } else if (TypeConversion.isS4(data.frameData.indexInEncodings)) {
            if (data.frameData.frame.isDeoptEntry) {
                return CodeInfoDecoder.FI_DEOPT_ENTRY_INDEX_S4;
            } else {
                return CodeInfoDecoder.FI_INFO_ONLY_INDEX_S4;
            }
        } else {
            throw new IllegalArgumentException();
        }
    }

    private static void writeDeoptFrameInfo(UnsafeArrayTypeWriter writeBuffer, IPData data, int entryFlags) {
        switch (CodeInfoDecoder.extractFI(entryFlags)) {
            case CodeInfoDecoder.FI_DEOPT_ENTRY_INDEX_S4:
            case CodeInfoDecoder.FI_INFO_ONLY_INDEX_S4:
                writeBuffer.putS4(data.frameData.indexInEncodings);
                break;
        }
    }

    public static boolean verifyMethod(SharedMethod method, CompilationResult compilation, int compilationOffset, CodeInfo info) {
        CodeInfoVerifier.verifyMethod(method, compilation, compilationOffset, info);
        return true;
    }

    public boolean verifyFrameInfo(CodeInfo info) {
        frameInfoEncoder.verifyEncoding(info);
        return true;
    }

    class AnnotationEncoder {
        boolean checkAnnotations(Annotation[] annotations, Annotation[][] parameterAnnotations) {
            try {
                encodeAnnotations(annotations);
                encodeParameterAnnotations(parameterAnnotations);
                return true;
            } catch (Throwable t) {
                return false;
            }
        }

        byte[] encodeAnnotations(Annotation[] annotations) throws InvocationTargetException, IllegalAccessException {
            UnsafeArrayTypeWriter buf = UnsafeArrayTypeWriter.create(ByteArrayReader.supportsUnalignedMemoryAccess());

            Annotation[] filteredAnnotations = filterAnnotations(annotations);
            buf.putU2(filteredAnnotations.length);
            for (Annotation annotation : filteredAnnotations) {
                encodeAnnotation(buf, annotation);
            }

            return buf.toArray();
        }

        byte[] encodeParameterAnnotations(Annotation[][] annotations) throws InvocationTargetException, IllegalAccessException {
            UnsafeArrayTypeWriter buf = UnsafeArrayTypeWriter.create(ByteArrayReader.supportsUnalignedMemoryAccess());

            buf.putU1(annotations.length);
            for (Annotation[] parameterAnnotations : annotations) {
                Annotation[] filteredParameterAnnotations = filterAnnotations(parameterAnnotations);
                buf.putU2(filteredParameterAnnotations.length);
                for (Annotation parameterAnnotation : filteredParameterAnnotations) {
                    encodeAnnotation(buf, parameterAnnotation);
                }
            }

            return buf.toArray();
        }

        void encodeAnnotation(UnsafeArrayTypeWriter buf, Annotation annotation) throws InvocationTargetException, IllegalAccessException {
            buf.putU2(encoders.sourceClasses.getIndex(annotation.annotationType()));
            AnnotationType type = AnnotationType.getInstance(annotation.annotationType());
            buf.putU2(type.members().size());
            for (Map.Entry<String, Method> entry : type.members().entrySet()) {
                String memberName = entry.getKey();
                Method valueAccessor = entry.getValue();
                buf.putU2(encoders.sourceMethodNames.getIndex(memberName));
                encodeValue(buf, valueAccessor.invoke(annotation), type.memberTypes().get(memberName));
            }
        }

        void encodeValue(UnsafeArrayTypeWriter buf, Object value, Class<?> type) throws InvocationTargetException, IllegalAccessException {
            buf.putU1(tag(type));
            if (type.isAnnotation()) {
                encodeAnnotation(buf, (Annotation) value);
            } else if (type.isEnum()) {
                buf.putU2(encoders.sourceClasses.getIndex(type));
                buf.putU2(encoders.sourceMethodNames.getIndex(((Enum<?>) value).name()));
            } else if (type.isArray()) {
                encodeArray(buf, value, type.getComponentType());
            } else if (type == Class.class) {
                buf.putU2(encoders.sourceClasses.getIndex((Class<?>) value));
            } else if (type == String.class) {
                buf.putU2(encoders.sourceMethodNames.getIndex((String) value));
            } else if (type.isPrimitive() || Wrapper.isWrapperType(type)) {
                Wrapper wrapper = type.isPrimitive() ? Wrapper.forPrimitiveType(type) : Wrapper.forWrapperType(type);
                switch (wrapper) {
                    case BOOLEAN:
                        buf.putU1((boolean) value ? 1 : 0);
                        break;
                    case BYTE:
                        buf.putS1((byte) value);
                        break;
                    case SHORT:
                        buf.putS2((short) value);
                        break;
                    case CHAR:
                        buf.putU2((char) value);
                        break;
                    case INT:
                        buf.putS4((int) value);
                        break;
                    case LONG:
                        buf.putS8((long) value);
                        break;
                    case FLOAT:
                        buf.putS4(Float.floatToRawIntBits((float) value));
                        break;
                    case DOUBLE:
                        buf.putS8(Double.doubleToRawLongBits((double) value));
                        break;
                    default:
                        throw shouldNotReachHere();
                }
            } else {
                throw shouldNotReachHere();
            }
        }

        void encodeArray(UnsafeArrayTypeWriter buf, Object value, Class<?> componentType) throws InvocationTargetException, IllegalAccessException {
            if (!componentType.isPrimitive()) {
                Object[] array = (Object[]) value;
                buf.putU2(array.length);
                for (Object val : array) {
                    encodeValue(buf, val, componentType);
                }
            } else if (componentType == boolean.class) {
                boolean[] array = (boolean[]) value;
                buf.putU2(array.length);
                for (boolean val : array) {
                    encodeValue(buf, val, componentType);
                }
            } else if (componentType == byte.class) {
                byte[] array = (byte[]) value;
                buf.putU2(array.length);
                for (byte val : array) {
                    encodeValue(buf, val, componentType);
                }
            } else if (componentType == short.class) {
                short[] array = (short[]) value;
                buf.putU2(array.length);
                for (short val : array) {
                    encodeValue(buf, val, componentType);
                }
            } else if (componentType == char.class) {
                char[] array = (char[]) value;
                buf.putU2(array.length);
                for (char val : array) {
                    encodeValue(buf, val, componentType);
                }
            } else if (componentType == int.class) {
                int[] array = (int[]) value;
                buf.putU2(array.length);
                for (int val : array) {
                    encodeValue(buf, val, componentType);
                }
            } else if (componentType == long.class) {
                long[] array = (long[]) value;
                buf.putU2(array.length);
                for (long val : array) {
                    encodeValue(buf, val, componentType);
                }
            } else if (componentType == float.class) {
                float[] array = (float[]) value;
                buf.putU2(array.length);
                for (float val : array) {
                    encodeValue(buf, val, componentType);
                }
            } else if (componentType == double.class) {
                double[] array = (double[]) value;
                buf.putU2(array.length);
                for (double val : array) {
                    encodeValue(buf, val, componentType);
                }
            }
        }

        byte tag(Class<?> type) {
            if (type.isAnnotation()) {
                return '@';
            } else if (type.isEnum()) {
                return 'e';
            } else if (type.isArray()) {
                return '[';
            } else if (type == Class.class) {
                return 'c';
            } else if (type == String.class) {
                return 's';
            } else if (type.isPrimitive()) {
                return (byte) Wrapper.forPrimitiveType(type).basicTypeChar();
            } else if (Wrapper.isWrapperType(type)) {
                return (byte) Wrapper.forWrapperType(type).basicTypeChar();
            } else {
                throw shouldNotReachHere();
            }
        }

        private Annotation[] filterAnnotations(Annotation[] annotations) {
            List<Annotation> filteredAnnotations = new ArrayList<>();
            for (Annotation annotation : annotations) {
                Class<? extends Annotation> annotationClass = annotation.annotationType();
                if (supportedValue(annotationClass, annotation, null)) {
                    filteredAnnotations.add(annotation);
                }
            }
            return filteredAnnotations.toArray(new Annotation[0]);
        }

        private void registerStrings(Annotation[] annotations) {
            for (Annotation annotation : annotations) {
                List<String> stringValues = new ArrayList<>();
                if (supportedValue(annotation.annotationType(), annotation, stringValues)) {
                    for (String stringValue : stringValues) {
                        encoders.sourceMethodNames.addObject(stringValue);
                    }
                }
            }
        }

        @SuppressWarnings("unchecked")
        private boolean supportedValue(Class<?> type, Object value, List<String> stringValues) {
            if (type.isAnnotation()) {
                Annotation annotation = (Annotation) value;
                if (!encoders.sourceClasses.contains(annotation.annotationType())) {
                    return false;
                }
                AnnotationType annotationType = AnnotationType.getInstance((Class<? extends Annotation>) type);
                for (Map.Entry<String, Class<?>> entry : annotationType.memberTypes().entrySet()) {
                    String valueName = entry.getKey();
                    Class<?> valueType = entry.getValue();
                    try {
                        Object annotationValue = annotationType.members().get(valueName).invoke(annotation);
                        if (!supportedValue(valueType, annotationValue, stringValues)) {
                            return false;
                        }
                    } catch (IllegalAccessException | InvocationTargetException e) {
                        return false;
                    }
                }
            } else if (type.isArray()) {
                boolean supported = true;
                Class<?> componentType = type.getComponentType();
                if (!componentType.isPrimitive()) {
                    for (Object val : (Object[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                } else if (componentType == boolean.class) {
                    for (boolean val : (boolean[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                } else if (componentType == byte.class) {
                    for (byte val : (byte[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                } else if (componentType == short.class) {
                    for (short val : (short[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                } else if (componentType == char.class) {
                    for (char val : (char[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                } else if (componentType == int.class) {
                    for (int val : (int[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                } else if (componentType == long.class) {
                    for (long val : (long[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                } else if (componentType == float.class) {
                    for (float val : (float[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                } else if (componentType == double.class) {
                    for (double val : (double[]) value) {
                        supported &= supportedValue(componentType, val, stringValues);
                    }
                }
                return supported;
            } else if (type == Class.class) {
                return encoders.sourceClasses.contains((Class<?>) value);
            } else if (type == String.class) {
                if (stringValues != null) {
                    stringValues.add((String) value);
                }
            } else if (type.isEnum()) {
                if (stringValues != null) {
                    stringValues.add(((Enum<?>) value).name());
                }
                return encoders.sourceClasses.contains(type);
            }
            return true;
        }
    }
}

class CodeInfoVerifier {
    static void verifyMethod(SharedMethod method, CompilationResult compilation, int compilationOffset, CodeInfo info) {
        for (int relativeIP = 0; relativeIP < compilation.getTargetCodeSize(); relativeIP++) {
            int totalIP = relativeIP + compilationOffset;
            CodeInfoQueryResult queryResult = new CodeInfoQueryResult();
            CodeInfoAccess.lookupCodeInfo(info, totalIP, queryResult);
            assert queryResult.isEntryPoint() == method.isEntryPoint();
            assert queryResult.hasCalleeSavedRegisters() == method.hasCalleeSavedRegisters();
            assert queryResult.getTotalFrameSize() == compilation.getTotalFrameSize();

            assert CodeInfoAccess.lookupStackReferenceMapIndex(info, totalIP) == queryResult.getReferenceMapIndex();
        }

        for (Infopoint infopoint : compilation.getInfopoints()) {
            if (infopoint.debugInfo != null) {
                int offset = CodeInfoEncoder.getEntryOffset(infopoint);
                if (offset >= 0) {
                    assert offset < compilation.getTargetCodeSize();
                    CodeInfoQueryResult queryResult = new CodeInfoQueryResult();
                    CodeInfoAccess.lookupCodeInfo(info, offset + compilationOffset, queryResult);

                    CollectingObjectReferenceVisitor visitor = new CollectingObjectReferenceVisitor();
                    CodeReferenceMapDecoder.walkOffsetsFromPointer(WordFactory.zero(), CodeInfoAccess.getStackReferenceMapEncoding(info), queryResult.getReferenceMapIndex(), visitor);
                    ReferenceMapEncoder.Input expected = (ReferenceMapEncoder.Input) infopoint.debugInfo.getReferenceMap();
                    visitor.result.verify();
                    assert expected.equals(visitor.result);

                    if (queryResult.frameInfo != CodeInfoQueryResult.NO_FRAME_INFO) {
                        verifyFrame(compilation, infopoint.debugInfo.frame(), queryResult.frameInfo, new BitSet());
                    }
                }
            }
        }

        for (ExceptionHandler handler : compilation.getExceptionHandlers()) {
            int offset = handler.pcOffset;
            assert offset >= 0 && offset < compilation.getTargetCodeSize();

            CodeInfoQueryResult queryResult = new CodeInfoQueryResult();
            CodeInfoAccess.lookupCodeInfo(info, offset + compilationOffset, queryResult);
            long actual = queryResult.getExceptionOffset();
            long expected = handler.handlerPos - handler.pcOffset;
            assert expected != 0;
            assert expected == actual;
        }
    }

    private static void verifyFrame(CompilationResult compilation, BytecodeFrame expectedFrame, FrameInfoQueryResult actualFrame, BitSet visitedVirtualObjects) {
        assert (expectedFrame == null) == (actualFrame == null);
        if (expectedFrame == null || !actualFrame.needLocalValues) {
            return;
        }
        verifyFrame(compilation, expectedFrame.caller(), actualFrame.getCaller(), visitedVirtualObjects);

        for (int i = 0; i < expectedFrame.values.length; i++) {
            JavaValue expectedValue = expectedFrame.values[i];
            if (i >= actualFrame.getValueInfos().length) {
                assert ValueUtil.isIllegalJavaValue(expectedValue);
                continue;
            }

            ValueInfo actualValue = actualFrame.getValueInfos()[i];

            JavaKind expectedKind = FrameInfoEncoder.getFrameValueKind(expectedFrame, i);
            assert expectedKind == actualValue.getKind();
            verifyValue(compilation, expectedValue, actualValue, actualFrame, visitedVirtualObjects);
        }
    }

    private static void verifyValue(CompilationResult compilation, JavaValue e, ValueInfo actualValue, FrameInfoQueryResult actualFrame, BitSet visitedVirtualObjects) {
        JavaValue expectedValue = e;

        if (expectedValue instanceof StackLockValue) {
            StackLockValue lock = (StackLockValue) expectedValue;
            assert ValueUtil.isIllegal(lock.getSlot());
            assert lock.isEliminated() == actualValue.isEliminatedMonitor();
            expectedValue = lock.getOwner();
        } else {
            assert actualValue.isEliminatedMonitor() == false;
        }

        if (ValueUtil.isIllegalJavaValue(expectedValue)) {
            assert actualValue.getType() == ValueType.Illegal;

        } else if (ValueUtil.isConstantJavaValue(expectedValue)) {
            assert actualValue.getType() == ValueType.Constant || actualValue.getType() == ValueType.DefaultConstant;
            JavaConstant expectedConstant = ValueUtil.asConstantJavaValue(expectedValue);
            JavaConstant actualConstant = actualValue.getValue();
            FrameInfoVerifier.verifyConstant(expectedConstant, actualConstant);

        } else if (expectedValue instanceof StackSlot) {
            assert actualValue.getType() == ValueType.StackSlot;
            int expectedOffset = ((StackSlot) expectedValue).getOffset(compilation.getTotalFrameSize());
            long actualOffset = actualValue.getData();
            assert expectedOffset == actualOffset;

        } else if (ReservedRegisters.singleton().isAllowedInFrameState(expectedValue)) {
            assert actualValue.getType() == ValueType.ReservedRegister;
            int expectedNumber = ValueUtil.asRegister((RegisterValue) expectedValue).number;
            long actualNumber = actualValue.getData();
            assert expectedNumber == actualNumber;

        } else if (CalleeSavedRegisters.supportedByPlatform() && expectedValue instanceof RegisterValue) {
            assert actualValue.getType() == ValueType.Register;
            int expectedOffset = CalleeSavedRegisters.singleton().getOffsetInFrame(ValueUtil.asRegister((RegisterValue) expectedValue));
            long actualOffset = actualValue.getData();
            assert expectedOffset == actualOffset;
            assert actualOffset < 0 : "Registers are stored in callee saved area of callee frame, i.e., with negative offset";

        } else if (ValueUtil.isVirtualObject(expectedValue)) {
            assert actualValue.getType() == ValueType.VirtualObject;
            int expectedId = ValueUtil.asVirtualObject(expectedValue).getId();
            long actualId = actualValue.getData();
            assert expectedId == actualId;

            verifyVirtualObject(compilation, ValueUtil.asVirtualObject(expectedValue), actualFrame.getVirtualObjects()[expectedId], actualFrame, visitedVirtualObjects);

        } else {
            throw shouldNotReachHere();
        }
    }

    private static void verifyVirtualObject(CompilationResult compilation, VirtualObject expectedObject, ValueInfo[] actualObject, FrameInfoQueryResult actualFrame, BitSet visitedVirtualObjects) {
        if (visitedVirtualObjects.get(expectedObject.getId())) {
            return;
        }
        visitedVirtualObjects.set(expectedObject.getId());

        ObjectLayout objectLayout = ConfigurationValues.getObjectLayout();
        SharedType expectedType = (SharedType) expectedObject.getType();

        // TODO assertion does not hold for now because expectedHub is java.lang.Class, but
        // actualHub is DynamicHub
        // ValueInfo actualHub = actualObject[0];
        // assert actualHub.getType() == ValueType.Constant && actualHub.getKind() ==
        // Kind.Object && expectedType.getObjectHub().equals(actualHub.getValue());

        if (expectedType.isArray()) {
            JavaKind kind = ((SharedType) expectedType.getComponentType()).getStorageKind();
            int expectedLength = 0;
            for (int i = 0; i < expectedObject.getValues().length; i++) {
                JavaValue expectedValue = expectedObject.getValues()[i];
                UnsignedWord expectedOffset = WordFactory.unsigned(objectLayout.getArrayElementOffset(kind, expectedLength));
                ValueInfo actualValue = findActualArrayElement(actualObject, expectedOffset);
                verifyValue(compilation, expectedValue, actualValue, actualFrame, visitedVirtualObjects);

                JavaKind valueKind = expectedObject.getSlotKind(i);
                if (objectLayout.sizeInBytes(kind) == 4 && objectLayout.sizeInBytes(valueKind) == 8) {
                    /*
                     * Truffle uses arrays in a non-standard way: it declares an int[] array and
                     * uses it to also store long and double values. These values span two array
                     * elements - so we have to add 2 to the length.
                     */
                    expectedLength += 2;
                } else {
                    expectedLength++;
                }
            }
            int actualLength = actualObject[1].value.asInt();
            assert expectedLength == actualLength;

        } else {
            SharedField[] expectedFields = (SharedField[]) expectedType.getInstanceFields(true);
            int fieldIdx = 0;
            int valueIdx = 0;
            while (valueIdx < expectedObject.getValues().length) {
                SharedField expectedField = expectedFields[fieldIdx];
                fieldIdx += 1;
                JavaValue expectedValue = expectedObject.getValues()[valueIdx];
                JavaKind valueKind = expectedObject.getSlotKind(valueIdx);
                valueIdx += 1;

                JavaKind kind = expectedField.getStorageKind();
                if (objectLayout.sizeInBytes(kind) == 4 && objectLayout.sizeInBytes(valueKind) == 8) {
                    /*
                     * Truffle uses fields in a non-standard way: it declares a couple of
                     * (consecutive) int fields, and uses them to also store long and double values.
                     * These values span two fields - so we have to ignore a field.
                     */
                    fieldIdx++;
                }

                UnsignedWord expectedOffset = WordFactory.unsigned(expectedField.getLocation());
                ValueInfo actualValue = findActualField(actualObject, expectedOffset);
                verifyValue(compilation, expectedValue, actualValue, actualFrame, visitedVirtualObjects);
            }
        }
    }

    private static ValueInfo findActualArrayElement(ValueInfo[] actualObject, UnsignedWord expectedOffset) {
        DynamicHub hub = (DynamicHub) SubstrateObjectConstant.asObject(actualObject[0].getValue());
        ObjectLayout objectLayout = ConfigurationValues.getObjectLayout();
        assert LayoutEncoding.isArray(hub.getLayoutEncoding());
        return findActualValue(actualObject, expectedOffset, objectLayout, LayoutEncoding.getArrayBaseOffset(hub.getLayoutEncoding()), 2);
    }

    private static ValueInfo findActualField(ValueInfo[] actualObject, UnsignedWord expectedOffset) {
        DynamicHub hub = (DynamicHub) SubstrateObjectConstant.asObject(actualObject[0].getValue());
        ObjectLayout objectLayout = ConfigurationValues.getObjectLayout();
        assert LayoutEncoding.isInstance(hub.getLayoutEncoding());
        return findActualValue(actualObject, expectedOffset, objectLayout, WordFactory.unsigned(objectLayout.getFirstFieldOffset()), 1);
    }

    private static ValueInfo findActualValue(ValueInfo[] actualObject, UnsignedWord expectedOffset, ObjectLayout objectLayout, UnsignedWord startOffset, int startIdx) {
        UnsignedWord curOffset = startOffset;
        int curIdx = startIdx;
        while (curOffset.belowThan(expectedOffset)) {
            ValueInfo value = actualObject[curIdx];
            curOffset = curOffset.add(objectLayout.sizeInBytes(value.getKind()));
            curIdx++;
        }
        if (curOffset.equal(expectedOffset)) {
            return actualObject[curIdx];
        }
        /*
         * If we go after the expected offset, return an illegal. Takes care of large byte array
         * accesses, and should raise flags for other cases.
         */
        ValueInfo illegal = new ValueInfo();
        illegal.type = ValueType.Illegal;
        return illegal;
    }
}

class CollectingObjectReferenceVisitor implements ObjectReferenceVisitor {
    protected final SubstrateReferenceMap result = new SubstrateReferenceMap();

    @Override
    public boolean visitObjectReference(Pointer objRef, boolean compressed) {
        return visitObjectReferenceInline(objRef, 0, compressed);
    }

    @Override
    public boolean visitObjectReferenceInline(Pointer objRef, int innerOffset, boolean compressed) {
        int derivedOffset = NumUtil.safeToInt(objRef.rawValue());
        result.markReferenceAtOffset(derivedOffset, derivedOffset - innerOffset, compressed);
        return true;
    }
}
