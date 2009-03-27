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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionListener;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import net.sourceforge.javacardsign.app.inputverifiers.CaretChangeListener;
import net.sourceforge.javacardsign.app.inputverifiers.PINInputVerifier;


public class UserAdministrationPane extends JPanel {

    private Vector<JComponent> components = new Vector<JComponent>();

    private PINInputVerifier pinInputVerifier = new PINInputVerifier(4, 20);

    private JPasswordField pin1 = null;

    private JPasswordField pin2 = null;

    private JPasswordField pin3 = null;

    public UserAdministrationPane(ActionListener listener) {
        super();
        setLayout(new GridBagLayout());

        JPanel pinsetPanel = new JPanel();
        pinsetPanel.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        double w = c.weightx;
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = w;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.EAST;
        c.insets = new Insets(5, 5, 5, 5);

        pinsetPanel.add(new JLabel("New PIN:"), c);
        c.gridy++;
        pinsetPanel.add(new JLabel("New PIN (repeat):"), c);

        c.anchor = GridBagConstraints.WEST;

        c.gridx = 1;
        c.gridy = 0;

        pin1 = new JPasswordField(21);
        pin1.setFont(MainGUI.FONT);
        pin1.setInputVerifier(pinInputVerifier);
        pin1.getCaret().addChangeListener(
                new CaretChangeListener(pin1, pinInputVerifier));
        components.add(pin1);
        pinsetPanel.add(pin1, c);

        c.gridy++;

        pin2 = new JPasswordField(21);
        pin2.setFont(MainGUI.FONT);
        pin2.setInputVerifier(pinInputVerifier);
        pin2.getCaret().addChangeListener(
                new CaretChangeListener(pin2, pinInputVerifier));
        components.add(pin2);
        pinsetPanel.add(pin2, c);

        c.gridx = 1;
        c.gridy = 2;

        JButton button = new JButton("Set PIN");
        button.setActionCommand("setpin");
        button.addActionListener(listener);
        components.add(button);
        pinsetPanel.add(button, c);

        c.gridx = 0;
        pinsetPanel.add(new JLabel(), c);

        c.gridx = 2;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        for (int i = 0; i < 3; i++) {
            c.gridy = i;
            pinsetPanel.add(new JLabel(), c);
        }
        pinsetPanel.setBorder(BorderFactory
                .createTitledBorder("Set / Change PIN"));

        JPanel pinverifyPanel = new JPanel();
        pinverifyPanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = w;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.EAST;
        c.insets = new Insets(5, 5, 5, 5);

        pinverifyPanel.add(new JLabel("Enter PIN:"), c);

        c.anchor = GridBagConstraints.WEST;
        c.gridx++;

        pin3 = new JPasswordField(21);
        pin3.setFont(MainGUI.FONT);
        pin3.setInputVerifier(pinInputVerifier);
        pin3.getCaret().addChangeListener(
                new CaretChangeListener(pin3, pinInputVerifier));
        components.add(pin3);
        pinverifyPanel.add(pin3, c);

        c.gridx++;

        button = new JButton("Verify PIN");
        button.setActionCommand("verifypin");
        button.addActionListener(listener);
        components.add(button);
        pinverifyPanel.add(button, c);

        c.gridx++;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        pinverifyPanel.add(new JLabel(), c);

        pinverifyPanel
                .setBorder(BorderFactory.createTitledBorder("Verify PIN"));

        c.gridx = 0;
        c.gridy = 0;
        c.weightx = w;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 0, 5, 0);

        add(pinsetPanel, c);
        c.gridy++;
        add(pinverifyPanel, c);

    }

    public void setEnabled(boolean flag) {
        for (JComponent c : components) {
            c.setEnabled(flag);
        }
    }

    public char[] getPIN1() {
        return pin1.getPassword();
    }

    public char[] getPIN2() {
        return pin2.getPassword();
    }

    public char[] getPIN3() {
        return pin3.getPassword();
    }

    public void clearPIN12() {
        pin1.setText("");
        pin2.setText("");
    }

    public void clearPIN3() {
        pin3.setText("");
    }

}
