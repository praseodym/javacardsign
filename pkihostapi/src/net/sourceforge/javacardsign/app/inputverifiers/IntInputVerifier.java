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

public class IntInputVerifier extends InputVerifier {

    private int min, max;

    public IntInputVerifier() {
        min = 0;
        max = 0x7FFF;

    }

    public IntInputVerifier(int min, int max) {
        this.min = min;
        this.max = max;
    }

    public boolean verify(JComponent input) {
        JTextField f = (JTextField) input;
        try {
            int i = Integer.parseInt(f.getText());
            if (i < min || i > max) {
                f.setForeground(Color.RED);
                return false;
            }
            f.setForeground(Color.BLACK);
            return true;
        } catch (NumberFormatException nfe) {
            f.setForeground(Color.RED);
            return false;
        }
    }
}
