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

package net.sourceforge.javacardsign.app;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPasswordField;

import net.sourceforge.javacardsign.app.inputverifiers.CaretChangeListener;
import net.sourceforge.javacardsign.app.inputverifiers.PINInputVerifier;


public class PINEnterDialog extends JDialog implements ActionListener {

    private JPasswordField pass = null;

    private char[] passVal = null;

    private PINInputVerifier pinInputVerifier;

    public PINEnterDialog(JFrame parent, String title, int minlen, int maxlen) {
        super(parent);
        setTitle(title);
        setLayout(new GridBagLayout());
        pinInputVerifier = new PINInputVerifier(minlen, maxlen);
        GridBagConstraints c = new GridBagConstraints();

        // ta = new JTextArea(100, 100);
        // ta.setText(contents);
        pass = new JPasswordField(maxlen + 1);
        pass.setFont(MainGUI.FONT);
        pass.addActionListener(this);
        pass.setInputVerifier(pinInputVerifier);
        pass.getCaret().addChangeListener(
                new CaretChangeListener(pass, pinInputVerifier));

        c.gridx = 0;
        c.gridwidth = 2;
        c.gridy = 0;
        c.fill = GridBagConstraints.BOTH;
        add(pass, c);

        c.gridwidth = 1;
        c.gridy++;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.CENTER;
        c.insets = new Insets(5, 0, 5, 20);

        JButton button = new JButton("OK");
        button.setActionCommand("ok");
        button.setMnemonic('O');
        button.setDefaultCapable(true);
        button.addActionListener(this);
        add(button, c);

        c.gridx++;

        button = new JButton("Cancel");
        button.setActionCommand("cancel");
        button.setMnemonic('C');
        button.addActionListener(this);
        add(button, c);

        setSize(new Dimension(200, 130));
        setResizable(false);
        setModal(true);
        setLocationRelativeTo(getParent());
        setVisible(true);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("ok") || e.getSource() == pass) {
            if (!pinInputVerifier.verify(pass))
                return;
            passVal = pass.getPassword();
            if (passVal.length == 0)
                passVal = null;
            dispose();
        }
        if (e.getActionCommand().equals("cancel")) {
            passVal = null;
            dispose();
        }

    }

    public char[] getPIN() {
        return passVal;
    }

}
