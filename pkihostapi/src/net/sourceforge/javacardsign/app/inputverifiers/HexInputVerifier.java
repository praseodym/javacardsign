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
import javax.swing.JTextArea;
import javax.swing.JTextField;

import net.sourceforge.javacardsign.service.Util;


public class HexInputVerifier extends InputVerifier {

    private int len;

    private boolean ignore = false;

    public HexInputVerifier(int reqlen) {
        len = reqlen;
    }

    public HexInputVerifier() {
        len = 0;
    }

    public void setIgnore(boolean flag) {
        ignore = flag;
    }

    public boolean verify(JComponent input) {

        String text = input instanceof JTextField ? ((JTextField) input)
                .getText() : ((JTextArea) input).getText();
        byte[] b = Util.stringToByteArray(text);
        if (!ignore && (b == null || (len != 0 && b.length != len))) {
            input.setForeground(Color.RED);
            return false;
        } else {
            input.setForeground(Color.BLACK);
            return true;
        }
    }
}
