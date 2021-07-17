/*
 * Copyright (c) 2019, 2019, Oracle and/or its affiliates. All rights reserved.
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
package com.oracle.svm.core.configure;

import java.util.List;

import com.oracle.svm.core.TypeResult;
import org.graalvm.nativeimage.impl.ConfigurationPredicate;

public interface ReflectionConfigurationParserDelegate<T> {

    TypeResult<T> resolveTypeResult(ConfigurationPredicate predicate, String typeName);

    void registerType(ConfigurationPredicate predicate, T type);

    void registerPublicClasses(ConfigurationPredicate predicate, T type);

    void registerDeclaredClasses(ConfigurationPredicate predicate, T type);

    void registerPublicFields(ConfigurationPredicate predicate, T type);

    void registerDeclaredFields(ConfigurationPredicate predicate, T type);

    void registerPublicMethods(ConfigurationPredicate predicate, T type);

    void registerDeclaredMethods(ConfigurationPredicate predicate, T type);

    void registerPublicConstructors(ConfigurationPredicate predicate, T type);

    void registerDeclaredConstructors(ConfigurationPredicate predicate, T type);

    void registerField(ConfigurationPredicate predicate, T type, String fieldName, boolean allowWrite) throws NoSuchFieldException;

    boolean registerAllMethodsWithName(ConfigurationPredicate predicate, T type, String methodName);

    void registerMethod(ConfigurationPredicate predicate, T type, String methodName, List<T> methodParameterTypes) throws NoSuchMethodException;

    void registerConstructor(ConfigurationPredicate predicate, T type, List<T> methodParameterTypes) throws NoSuchMethodException;

    boolean registerAllConstructors(ConfigurationPredicate predicate, T type);

    String getTypeName(T type);

    String getSimpleName(T type);

}
