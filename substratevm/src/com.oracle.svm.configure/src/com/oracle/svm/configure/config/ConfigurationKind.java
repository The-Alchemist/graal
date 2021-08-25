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

import java.util.HashMap;
import java.util.Map;

public final class ConfigurationKind {
    private static Map<ConfigurationMemberKind, Map<ConfigurationAccessKind, ConfigurationKind>> cache = new HashMap<>();

    private final ConfigurationMemberKind memberKind;
    private final ConfigurationAccessKind accessKind;

    private ConfigurationKind(ConfigurationMemberKind memberKind, ConfigurationAccessKind accessKind) {
        this.memberKind = memberKind;
        this.accessKind = accessKind;
    }

    public ConfigurationMemberKind getMemberKind() {
        return memberKind;
    }

    public ConfigurationAccessKind getAccessKind() {
        return accessKind;
    }

    public static ConfigurationKind get(ConfigurationMemberKind memberKind, ConfigurationAccessKind accessKind) {
        return cache.computeIfAbsent(memberKind, k -> new HashMap<>()).computeIfAbsent(accessKind, k -> new ConfigurationKind(memberKind, accessKind));
    }

    public enum ConfigurationMemberKind {
        /**
         * The member is public and declared in the type in question.
         */
        DECLARED_AND_PUBLIC,

        /**
         * The member is declared in the type in question.
         */
        DECLARED,

        /**
         * The member is public and is either declared or inherited in the type in question.
         */
        PUBLIC,

        /**
         * The member is either declared or inherited in the type in question.
         */
        PRESENT;

        private boolean isMoreSpecificThan(ConfigurationMemberKind other) {
            return other == null || ordinal() < other.ordinal();
        }

        public ConfigurationMemberKind intersect(ConfigurationMemberKind other) {
            if (equals(DECLARED) && PUBLIC.equals(other) || equals(PUBLIC) && DECLARED.equals(other)) {
                return DECLARED_AND_PUBLIC;
            }
            return this.isMoreSpecificThan(other) ? this : other;
        }

        private ConfigurationMemberKind union(ConfigurationMemberKind other) {
            return equals(other) ? this : PRESENT;
        }

        public boolean includes(ConfigurationMemberKind other) {
            if (equals(DECLARED_AND_PUBLIC)) {
                return DECLARED.equals(other) || PUBLIC.equals(other);
            }
            if (equals(PRESENT)) {
                return true;
            }
            return equals(other);
        }
    }

    public enum ConfigurationAccessKind {
        NONE,
        QUERIED,
        ACCESSED;

        public ConfigurationAccessKind combine(ConfigurationAccessKind other) {
            return (ordinal() < other.ordinal()) ? other : this;
        }

        public ConfigurationAccessKind remove(ConfigurationAccessKind other) {
            return other.includes(this) ? NONE : this;
        }

        public boolean includes(ConfigurationAccessKind other) {
            return ordinal() >= other.ordinal();
        }
    }

    public ConfigurationKind intersect(ConfigurationKind other) {
        return get(memberKind.intersect(other.memberKind), accessKind.combine(other.accessKind));
    }

    public ConfigurationKind union(ConfigurationKind other) {
        return get(memberKind.union(other.memberKind), accessKind.combine(other.accessKind));
    }

    public boolean includes(ConfigurationKind other) {
        return memberKind.includes(other.memberKind) && accessKind.includes(other.accessKind);
    }
}
