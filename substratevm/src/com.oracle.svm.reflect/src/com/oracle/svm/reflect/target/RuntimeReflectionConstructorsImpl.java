/*
 * Copyright (c) 2012, 2020, Oracle and/or its affiliates. All rights reserved.
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
package com.oracle.svm.reflect.target;

// Checkstyle: stop
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
// Checkstyle: resume

import com.oracle.svm.core.SubstrateUtil;
import com.oracle.svm.core.reflect.RuntimeReflectionConstructors;

import jdk.vm.ci.meta.MetaUtil;

public class RuntimeReflectionConstructorsImpl implements RuntimeReflectionConstructors {
    @Override
    public Method newMethod(Class<?> declaringClass, String name, Class<?>[] parameterTypes, Class<?> returnType, Class<?>[] checkedExceptions, int modifiers,
                    byte[] annotations, byte[] parameterAnnotations, byte[] annotationDefault) {
        Target_java_lang_reflect_Method method = new Target_java_lang_reflect_Method();
        String signature = toInternalSignature(returnType, parameterTypes);
        method.constructor(declaringClass, name, parameterTypes, returnType, checkedExceptions, modifiers, -1, signature, annotations, parameterAnnotations, null);
        return SubstrateUtil.cast(method, Method.class);
    }

    @Override
    public Constructor<?> newConstructor(Class<?> declaringClass, Class<?>[] parameterTypes, Class<?>[] checkedExceptions, int modifiers, byte[] annotations,
                    byte[] parameterAnnotations) {
        Target_java_lang_reflect_Constructor cons = new Target_java_lang_reflect_Constructor();
        String signature = toInternalSignature(void.class, parameterTypes);
        cons.constructor(declaringClass, parameterTypes, checkedExceptions, modifiers, -1, signature, annotations, parameterAnnotations);
        return SubstrateUtil.cast(cons, Constructor.class);
    }

    private static String toInternalSignature(Class<?> returnType, Class<?>[] parameterTypes) {
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> type : parameterTypes) {
            sb.append(MetaUtil.toInternalName(type.getName()));
        }
        sb.append(')');
        sb.append(MetaUtil.toInternalName(returnType.getName()));
        return sb.toString();
    }
}
