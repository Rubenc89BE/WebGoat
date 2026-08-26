/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.deserialization;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Set;

/**
 * A validating ObjectInputStream that implements class allowlisting to prevent deserialization of
 * untrusted classes. This mitigates arbitrary code execution via malicious serialized objects.
 *
 * <p>Only classes explicitly listed in the allowlist can be deserialized. This prevents attackers
 * from deserializing gadget classes that could execute arbitrary code during readObject().
 */
public class ValidatingObjectInputStream extends ObjectInputStream {

  private static final Set<String> ALLOWED_CLASSES =
      Set.of(
          // Allow the specific class needed for this lesson
          "org.dummy.insecure.framework.VulnerableTaskHolder",
          // Allow necessary Java standard library classes
          "java.time.LocalDateTime",
          "java.time.Ser",
          // Allow primitive arrays and basic types
          "[B", // byte array
          "[C", // char array
          "[I", // int array
          "[J", // long array
          "[F", // float array
          "[D", // double array
          "[Z", // boolean array
          "[S", // short array
          "java.lang.String",
          "java.lang.Number",
          "java.lang.Integer",
          "java.lang.Long",
          "java.lang.Float",
          "java.lang.Double",
          "java.lang.Boolean",
          "java.lang.Byte",
          "java.lang.Short",
          "java.lang.Character");

  public ValidatingObjectInputStream(InputStream in) throws IOException {
    super(in);
  }

  @Override
  protected Class<?> resolveClass(ObjectStreamClass desc)
      throws IOException, ClassNotFoundException {
    String className = desc.getName();

    // Check if the class is in the allowlist
    if (!isAllowedClass(className)) {
      throw new InvalidClassException(
          "Unauthorized deserialization attempt: class " + className + " is not allowed");
    }

    return super.resolveClass(desc);
  }

  /**
   * Checks if a class name is allowed for deserialization.
   *
   * @param className the fully qualified class name
   * @return true if the class is allowed, false otherwise
   */
  private boolean isAllowedClass(String className) {
    // Check exact match in allowlist
    if (ALLOWED_CLASSES.contains(className)) {
      return true;
    }

    // Allow arrays of allowed classes
    if (className.startsWith("[L") && className.endsWith(";")) {
      String elementClass = className.substring(2, className.length() - 1);
      return ALLOWED_CLASSES.contains(elementClass);
    }

    return false;
  }
}
