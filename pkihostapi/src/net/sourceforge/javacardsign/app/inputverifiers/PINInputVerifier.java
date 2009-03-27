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

package net.sourceforge.javacardsign.app.inputverifiers;

import java.awt.Color;

import javax.swing.InputVerifier;
import javax.swing.JComponent;
import javax.swing.JTextField;

public class PINInputVerifier extends InputVerifier {

    private int minlen, maxlen;

    public PINInputVerifier(int minnum, int maxnum) {
        minlen = minnum;
        maxlen = maxnum;
    }

    public PINInputVerifier() {
        minlen = 4;
        maxlen = 20;
    }

    public boolean verify(JComponent input) {

        JTextField f = (JTextField) input;
        String s = f.getText();
        if (s.length() < minlen || s.length() > maxlen) {
            if (s.length() == 0) {
                f.setForeground(Color.BLACK);
                return true;
            }
            f.setForeground(Color.RED);
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                f.setForeground(Color.RED);
                return false;
            }
        }
        f.setForeground(Color.BLACK);
        return true;
    }
}
