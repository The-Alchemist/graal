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
package com.oracle.svm.configure.config;

import java.io.IOException;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.oracle.svm.configure.config.ConfigurationKind.ConfigurationAccessKind;
import com.oracle.svm.configure.config.ConfigurationKind.ConfigurationMemberKind;
import com.oracle.svm.configure.json.JsonPrintable;
import com.oracle.svm.configure.json.JsonPrinter;
import com.oracle.svm.configure.json.JsonWriter;

public class ConfigurationType implements JsonPrintable {
    private final String qualifiedJavaName;

    private Map<String, FieldInfo> fields;
    private Map<ConfigurationMethod, ConfigurationKind> methods;

    private boolean allDeclaredClasses;
    private boolean allPublicClasses;
    private boolean allDeclaredFields;
    private boolean allPublicFields;
    private ConfigurationAccessKind allDeclaredMethodsAccess = ConfigurationAccessKind.NONE;
    private ConfigurationAccessKind allPublicMethodsAccess = ConfigurationAccessKind.NONE;
    private ConfigurationAccessKind allDeclaredConstructorsAccess = ConfigurationAccessKind.NONE;
    private ConfigurationAccessKind allPublicConstructorsAccess = ConfigurationAccessKind.NONE;

    public ConfigurationType(String qualifiedJavaName) {
        assert qualifiedJavaName.indexOf('/') == -1 : "Requires qualified Java name, not internal representation";
        assert !qualifiedJavaName.startsWith("[") : "Requires Java source array syntax, for example java.lang.String[]";
        this.qualifiedJavaName = qualifiedJavaName;
    }

    public ConfigurationType(ConfigurationType other) {
        qualifiedJavaName = other.qualifiedJavaName;
        mergeWith(other);
    }

    public void mergeWith(ConfigurationType other) {
        assert qualifiedJavaName.equals(other.qualifiedJavaName);
        mergeFlagsWith(other);
        mergeFieldsWith(other);
        mergeMethodsWith(other);
    }

    private void mergeFlagsWith(ConfigurationType other) {
        setFlagsFromOtherUsingPredicate(other, (our, their) -> our || their, ConfigurationAccessKind::combine);
    }

    private void mergeFieldsWith(ConfigurationType other) {
        if (other.fields != null) {
            if (fields == null) {
                fields = new HashMap<>();
            }
            for (Map.Entry<String, FieldInfo> fieldInfoEntry : other.fields.entrySet()) {
                fields.compute(fieldInfoEntry.getKey(), (key, value) -> {
                    if (value == null) {
                        return fieldInfoEntry.getValue();
                    } else {
                        return value.newMergedWith(fieldInfoEntry.getValue());
                    }
                });
            }
        }
        maybeRemoveFields(allDeclaredFields, allPublicFields);
    }

    private void maybeRemoveFields(boolean hasAllDeclaredFields, boolean hasAllPublicFields) {
        if (hasAllDeclaredFields) {
            removeFields(ConfigurationMemberKind.DECLARED);
        }
        if (hasAllPublicFields) {
            removeFields(ConfigurationMemberKind.PUBLIC);
        }
    }

    private void mergeMethodsWith(ConfigurationType other) {
        if (other.methods != null) {
            if (methods == null) {
                methods = new HashMap<>();
            }
            for (Map.Entry<ConfigurationMethod, ConfigurationKind> methodEntry : other.methods.entrySet()) {
                methods.compute(methodEntry.getKey(), (key, value) -> {
                    if (value != null) {
                        return value.intersect(methodEntry.getValue()); // TODO check (different
                                                                        // from before)
                    } else {
                        return methodEntry.getValue();
                    }
                });
            }
        }
        maybeRemoveMethods(allDeclaredMethodsAccess, allPublicMethodsAccess, allDeclaredConstructorsAccess, allPublicConstructorsAccess);
    }

    private void maybeRemoveMethods(ConfigurationAccessKind hasAllDeclaredMethods, ConfigurationAccessKind hasAllPublicMethods, ConfigurationAccessKind hasAllDeclaredConstructors,
                    ConfigurationAccessKind hasAllPublicConstructors) {
        if (hasAllDeclaredMethods != ConfigurationAccessKind.NONE) {
            removeMethods(ConfigurationMemberKind.DECLARED, hasAllDeclaredMethods, false);
        }
        if (hasAllDeclaredConstructors != ConfigurationAccessKind.NONE) {
            removeMethods(ConfigurationMemberKind.DECLARED, hasAllDeclaredConstructors, true);
        }

        if (hasAllPublicMethods != ConfigurationAccessKind.NONE) {
            removeMethods(ConfigurationMemberKind.PUBLIC, hasAllPublicMethods, false);
        }
        if (hasAllPublicConstructors != ConfigurationAccessKind.NONE) {
            removeMethods(ConfigurationMemberKind.PUBLIC, hasAllPublicConstructors, true);
        }
    }

    public void removeAll(ConfigurationType other) {
        removeFlags(other);
        removeFields(other);
        removeMethods(other);
    }

    private void removeFlags(ConfigurationType other) {
        setFlagsFromOtherUsingPredicate(other, (our, their) -> our && !their, ConfigurationAccessKind::remove);
    }

    private void removeFields(ConfigurationType other) {
        maybeRemoveFields(allDeclaredFields || other.allDeclaredFields, allPublicFields || other.allPublicFields);
        if (fields != null && other.fields != null) {
            for (Map.Entry<String, FieldInfo> fieldInfoEntry : other.fields.entrySet()) {
                fields.computeIfPresent(fieldInfoEntry.getKey(), (key, value) -> value.newWithDifferencesFrom(fieldInfoEntry.getValue()));
            }
            if (fields.isEmpty()) {
                fields = null;
            }
        }
    }

    private void removeMethods(ConfigurationType other) {
        maybeRemoveMethods(allDeclaredMethodsAccess.combine(other.allDeclaredMethodsAccess), allPublicMethodsAccess.combine(other.allPublicMethodsAccess),
                        allDeclaredConstructorsAccess.combine(other.allDeclaredConstructorsAccess), allPublicConstructorsAccess.combine(other.allPublicConstructorsAccess));
        if (methods != null && other.methods != null) {
            methods.entrySet().removeAll(other.methods.entrySet());
            if (methods.isEmpty()) {
                methods = null;
            }
        }
    }

    private void setFlagsFromOtherUsingPredicate(ConfigurationType other, BiPredicate<Boolean, Boolean> flagPredicate,
                    BiFunction<ConfigurationAccessKind, ConfigurationAccessKind, ConfigurationAccessKind> accessPredicate) {
        allDeclaredClasses = flagPredicate.test(allDeclaredClasses, other.allDeclaredClasses);
        allPublicClasses = flagPredicate.test(allPublicClasses, other.allPublicClasses);
        allDeclaredFields = flagPredicate.test(allDeclaredFields, other.allDeclaredFields);
        allPublicFields = flagPredicate.test(allPublicFields, other.allPublicFields);
        allDeclaredMethodsAccess = accessPredicate.apply(allDeclaredMethodsAccess, other.allDeclaredMethodsAccess);
        allPublicMethodsAccess = accessPredicate.apply(allPublicMethodsAccess, other.allPublicMethodsAccess);
        allDeclaredConstructorsAccess = accessPredicate.apply(allDeclaredConstructorsAccess, other.allDeclaredConstructorsAccess);
        allPublicConstructorsAccess = accessPredicate.apply(allPublicConstructorsAccess, other.allPublicConstructorsAccess);
    }

    public boolean isEmpty() {
        return methods == null && fields == null && allFlagsFalse();
    }

    private boolean allFlagsFalse() {
        return !(allDeclaredClasses || allPublicClasses || allDeclaredFields || allPublicFields ||
                        allDeclaredMethodsAccess != ConfigurationAccessKind.NONE || allPublicMethodsAccess != ConfigurationAccessKind.NONE ||
                        allDeclaredConstructorsAccess != ConfigurationAccessKind.NONE || allPublicConstructorsAccess != ConfigurationAccessKind.NONE);
    }

    public String getQualifiedJavaName() {
        return qualifiedJavaName;
    }

    public void addField(String name, ConfigurationMemberKind memberKind, boolean finalButWritable) {
        if (!finalButWritable) {
            if ((memberKind.includes(ConfigurationMemberKind.DECLARED) && haveAllDeclaredFields()) || (memberKind.includes(ConfigurationMemberKind.PUBLIC) && haveAllPublicFields())) {
                fields = maybeRemove(fields, map -> {
                    FieldInfo fieldInfo = map.get(name);
                    if (fieldInfo != null && !fieldInfo.isFinalButWritable()) {
                        map.remove(name);
                    }
                });
                return;
            }
        }
        if (fields == null) {
            fields = new HashMap<>();
        }
        fields.compute(name, (k, v) -> (v != null)
                        ? FieldInfo.get(v.getKind().intersect(memberKind), v.isFinalButWritable() || finalButWritable)
                        : FieldInfo.get(memberKind, finalButWritable));
    }

    public void addMethodsWithName(String name, ConfigurationMemberKind memberKind) {
        addMethod(name, null, memberKind, ConfigurationAccessKind.ACCESSED);
    }

    public void addMethodsWithName(String name, ConfigurationMemberKind memberKind, ConfigurationAccessKind accessKind) {
        addMethod(name, null, memberKind, accessKind);
    }

    public void addMethod(String name, String internalSignature, ConfigurationMemberKind memberKind) {
        addMethod(name, internalSignature, memberKind, ConfigurationAccessKind.ACCESSED);
    }

    public void addMethod(String name, String internalSignature, ConfigurationMemberKind memberKind, ConfigurationAccessKind accessKind) {
        ConfigurationKind kind = ConfigurationKind.get(memberKind, accessKind);
        boolean matchesAllSignatures = (internalSignature == null);
        if (ConfigurationMethod.isConstructorName(name) ? hasAllConstructors(memberKind, accessKind) : hasAllMethods(memberKind, accessKind)) {
            if (!matchesAllSignatures) {
                methods = maybeRemove(methods, map -> map.remove(new ConfigurationMethod(name, internalSignature)));
            }
            return;
        }
        if (methods == null) {
            methods = new HashMap<>();
        }
        ConfigurationMethod method = new ConfigurationMethod(name, internalSignature);
        if (matchesAllSignatures) { // remove any methods that the new entry matches
            methods.compute(method, (k, v) -> v != null ? kind.union(v) : kind);
            methods = maybeRemove(methods, map -> map.entrySet().removeIf(entry -> name.equals(entry.getKey().getName()) &&
                            kind.includes(entry.getValue()) && !method.equals(entry.getKey())));
        } else {
            methods.compute(method, (k, v) -> v != null ? kind.intersect(v) : kind);
        }
        assert methods.containsKey(method);
    }

    private boolean hasAllConstructors(ConfigurationMemberKind memberKind, ConfigurationAccessKind accessKind) {
        return (memberKind.includes(ConfigurationMemberKind.DECLARED) && allDeclaredConstructorsAccess.includes(accessKind)) ||
                        (memberKind.includes(ConfigurationMemberKind.PUBLIC) && allPublicConstructorsAccess.includes(accessKind));
    }

    private boolean hasAllMethods(ConfigurationMemberKind memberKind, ConfigurationAccessKind accessKind) {
        return (memberKind.includes(ConfigurationMemberKind.DECLARED) && allDeclaredMethodsAccess.includes(accessKind)) ||
                        (memberKind.includes(ConfigurationMemberKind.PUBLIC) && allPublicMethodsAccess.includes(accessKind));
    }

    public ConfigurationKind getMethodKindIfPresent(ConfigurationMethod method) {
        return methods == null ? null : methods.get(method);
    }

    public FieldInfo getFieldInfoIfPresent(String field) {
        return fields == null ? null : fields.get(field);
    }

    public boolean haveAllDeclaredClasses() {
        return allDeclaredClasses;
    }

    public boolean haveAllPublicClasses() {
        return allPublicClasses;
    }

    public void setAllDeclaredClasses() {
        this.allDeclaredClasses = true;
    }

    public void setAllPublicClasses() {
        this.allPublicClasses = true;
    }

    public boolean haveAllDeclaredFields() {
        return allDeclaredFields;
    }

    public boolean haveAllPublicFields() {
        return allPublicFields;
    }

    public void setAllDeclaredFields() {
        this.allDeclaredFields = true;
        removeFields(ConfigurationMemberKind.DECLARED);
    }

    public void setAllPublicFields() {
        this.allPublicFields = true;
        removeFields(ConfigurationMemberKind.PUBLIC);
    }

    public ConfigurationAccessKind getAllDeclaredMethods() {
        return allDeclaredMethodsAccess;
    }

    public ConfigurationAccessKind getAllPublicMethods() {
        return allPublicMethodsAccess;
    }

    public void setAllDeclaredMethods(ConfigurationAccessKind accessKind) {
        if (!this.allDeclaredMethodsAccess.includes(accessKind)) {
            this.allDeclaredMethodsAccess = accessKind;
            removeMethods(ConfigurationMemberKind.DECLARED, accessKind, false);
        }
    }

    public void setAllPublicMethods(ConfigurationAccessKind accessKind) {
        if (!this.allPublicMethodsAccess.includes(accessKind)) {
            this.allPublicMethodsAccess = accessKind;
            removeMethods(ConfigurationMemberKind.PUBLIC, accessKind, false);
        }
    }

    public ConfigurationAccessKind getAllDeclaredConstructors() {
        return allDeclaredConstructorsAccess;
    }

    public ConfigurationAccessKind getAllPublicConstructors() {
        return allPublicConstructorsAccess;
    }

    public void setAllDeclaredConstructors(ConfigurationAccessKind accessKind) {
        if (!this.allDeclaredConstructorsAccess.includes(accessKind)) {
            this.allDeclaredConstructorsAccess = accessKind;
            removeMethods(ConfigurationMemberKind.DECLARED, accessKind, true);
        }
    }

    public void setAllPublicConstructors(ConfigurationAccessKind accessKind) {
        if (!this.allPublicConstructorsAccess.includes(accessKind)) {
            this.allPublicConstructorsAccess = accessKind;
            removeMethods(ConfigurationMemberKind.PUBLIC, accessKind, true);
        }
    }

    @Override
    public void printJson(JsonWriter writer) throws IOException {
        writer.append('{').indent().newline();
        writer.quote("name").append(':').quote(qualifiedJavaName);
        optionallyPrintJsonBoolean(writer, haveAllDeclaredFields(), "allDeclaredFields");
        optionallyPrintJsonBoolean(writer, haveAllPublicFields(), "allPublicFields");
        optionallyPrintJsonBoolean(writer, getAllDeclaredMethods() == ConfigurationAccessKind.ACCESSED, "allDeclaredMethods");
        optionallyPrintJsonBoolean(writer, getAllPublicMethods() == ConfigurationAccessKind.ACCESSED, "allPublicMethods");
        optionallyPrintJsonBoolean(writer, getAllDeclaredConstructors() == ConfigurationAccessKind.ACCESSED, "allDeclaredConstructors");
        optionallyPrintJsonBoolean(writer, getAllPublicConstructors() == ConfigurationAccessKind.ACCESSED, "allPublicConstructors");
        optionallyPrintJsonBoolean(writer, haveAllDeclaredClasses(), "allDeclaredClasses");
        optionallyPrintJsonBoolean(writer, haveAllPublicClasses(), "allPublicClasses");
        optionallyPrintJsonBoolean(writer, getAllDeclaredMethods() == ConfigurationAccessKind.QUERIED, "queryAllDeclaredMethods");
        optionallyPrintJsonBoolean(writer, getAllPublicMethods() == ConfigurationAccessKind.QUERIED, "queryAllPublicMethods");
        optionallyPrintJsonBoolean(writer, getAllDeclaredConstructors() == ConfigurationAccessKind.QUERIED, "queryAllDeclaredConstructors");
        optionallyPrintJsonBoolean(writer, getAllPublicConstructors() == ConfigurationAccessKind.QUERIED, "queryAllPublicConstructors");
        if (fields != null) {
            writer.append(',').newline().quote("fields").append(':');
            JsonPrinter.printCollection(writer, fields.entrySet(), Map.Entry.comparingByKey(), ConfigurationType::printField);
        }
        if (methods != null) {
            Set<ConfigurationMethod> accessedMethods = getMethodsForAccessKind(ConfigurationAccessKind.ACCESSED);
            if (!accessedMethods.isEmpty()) {
                writer.append(',').newline().quote("methods").append(':');
                JsonPrinter.printCollection(writer,
                                accessedMethods,
                                Comparator.comparing(ConfigurationMethod::getName).thenComparing(Comparator.nullsFirst(Comparator.comparing(ConfigurationMethod::getInternalSignature))),
                                JsonPrintable::printJson);
            }
            Set<ConfigurationMethod> queriedMethods = getMethodsForAccessKind(ConfigurationAccessKind.QUERIED);
            if (!queriedMethods.isEmpty()) {
                writer.append(',').newline().quote("queriedMethods").append(':');
                JsonPrinter.printCollection(writer,
                                queriedMethods,
                                Comparator.comparing(ConfigurationMethod::getName).thenComparing(Comparator.nullsFirst(Comparator.comparing(ConfigurationMethod::getInternalSignature))),
                                JsonPrintable::printJson);
            }
        }
        writer.unindent().newline();
        writer.append('}');
    }

    private Set<ConfigurationMethod> getMethodsForAccessKind(ConfigurationAccessKind accessKind) {
        return methods.entrySet().stream().filter(e -> e.getValue().getAccessKind() == accessKind).map(Map.Entry::getKey).collect(Collectors.toSet());
    }

    private static void printField(Map.Entry<String, FieldInfo> entry, JsonWriter w) throws IOException {
        w.append('{').quote("name").append(':').quote(entry.getKey());
        if (entry.getValue().isFinalButWritable()) {
            w.append(", ").quote("allowWrite").append(':').append("true");
        }
        w.append('}');
    }

    private static void optionallyPrintJsonBoolean(JsonWriter writer, boolean predicate, String attribute) throws IOException {
        if (predicate) {
            writer.append(',').newline().quote(attribute).append(":true");
        }
    }

    private void removeFields(ConfigurationMemberKind memberKind) {
        fields = maybeRemove(fields, map -> map.values().removeIf(v -> memberKind.includes(v.getKind())));
    }

    private void removeMethods(ConfigurationMemberKind memberKind, ConfigurationAccessKind accessKind, boolean constructors) {
        ConfigurationKind kind = ConfigurationKind.get(memberKind, accessKind);
        methods = maybeRemove(methods, map -> map.entrySet().removeIf(entry -> entry.getKey().isConstructor() == constructors && kind.includes(entry.getValue())));
    }

    private static <T, S> Map<T, S> maybeRemove(Map<T, S> fromMap, Consumer<Map<T, S>> action) {
        Map<T, S> map = fromMap;
        if (map != null) {
            action.accept(map);
            if (map.isEmpty()) {
                map = null;
            }
        }
        return map;
    }
}
