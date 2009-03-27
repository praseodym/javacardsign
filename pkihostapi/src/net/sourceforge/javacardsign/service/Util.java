/*
 * Java Card PKI host API - A Java API for accessing ISO7816
 * compliant PKI cards. 
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package net.sourceforge.javacardsign.service;

public class Util {
    public static String byteArrayToString(byte[] a, boolean space) {
        return byteArrayToString(a, space, 65536);
    }

    public static String byteArrayToString(byte[] a, boolean space, int split) {
        if (a == null)
            return "NULL";
        String sep = space ? " " : "";
        String result = "";
        String onebyte = null;
        for (int i = 0; i < a.length; i++) {
            if (i != 0 && (i % split) == 0) {
                result = result + "\n";
            }
            onebyte = Integer.toHexString(a[i]);
            if (onebyte.length() == 1)
                onebyte = "0" + onebyte;
            else
                onebyte = onebyte.substring(onebyte.length() - 2);
            result = result + onebyte.toUpperCase() + sep;
        }
        return result;
    }

    /**
     * Returns a byte array contained in a string. The string can be terminated
     * with a semicolon.
     */
    public static byte[] stringToByteArray(String s) {
        java.util.Vector<Integer> v = new java.util.Vector<Integer>();
        String operate = new String(s);
        operate = operate.replaceAll(" ", "");
        operate = operate.replaceAll("\t", "");
        operate = operate.replaceAll("\n", "");
        if (operate.endsWith(";"))
            operate = operate.substring(0, operate.length() - 1);
        if (operate.length() % 2 != 0)
            return null;
        int num = 0;
        while (operate.length() > 0) {
            try {
                num = Integer.parseInt(operate.substring(0, 2), 16);
            } catch (NumberFormatException nfe) {
                return null;
            }
            v.add(new Integer(num));
            operate = operate.substring(2);
        }
        byte[] result = new byte[v.size()];
        java.util.Iterator<Integer> it = v.iterator();
        int i = 0;
        while (it.hasNext())
            result[i++] = it.next().byteValue();
        return result;
    }

}
