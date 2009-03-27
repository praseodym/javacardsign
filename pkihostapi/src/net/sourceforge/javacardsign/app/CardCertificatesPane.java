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

import java.awt.Color;
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
import javax.swing.JTextField;

public class CardCertificatesPane extends JPanel {
    private Vector<JComponent> components = new Vector<JComponent>();

    private boolean[] enabledCerts = new boolean[3];

    private JTextField[] verifyFlags = null;

    private JTextField[] certNames = null;

    private JButton[] clearButtons = null;

    private JButton[] viewButtons = null;

    private JButton[] verifyButtons = null;

    private int totalCerts;

    private static String[] ulabels = new String[] { "Auth", "Sign", "Dec" };

    private int baseIndex;

    public CardCertificatesPane(boolean ca, ActionListener listener) {
        super();
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        double w = c.weightx;

        c.insets = new Insets(5, 0, 5, 10);
        JButton button = null;
        String label = null;
        baseIndex = ca ? 0 : 3;

        clearButtons = new JButton[3];
        viewButtons = new JButton[3];
        certNames = new JTextField[3];
        if (!ca) {
            verifyButtons = new JButton[3];
            verifyFlags = new JTextField[3];
        }

        totalCerts = ca ? 1 : 3;
        for (int i = 0; i < totalCerts; i++) {
            c.gridx = 0;
            c.gridy = i;
            c.weightx = w;
            c.fill = GridBagConstraints.NONE;
            c.anchor = GridBagConstraints.EAST;
            if (ca) {
                label = "CA Cert";
            } else {
                label = ulabels[i] + " Cert";
            }
            add(new JLabel(label + ":"), c);

            c.anchor = GridBagConstraints.WEST;
            c.gridx++;

            button = new JButton("Get from Card");
            button.setActionCommand("cardgetcert" + (baseIndex + i));
            button.addActionListener(listener);
            components.add(button);
            add(button, c);

            c.gridx++;

            button = new JButton("Load...");
            button.setActionCommand("loadcert" + (baseIndex + i));
            button.addActionListener(listener);
            components.add(button);
            add(button, c);

            c.gridx++;

            certNames[i] = new JTextField(30);
            certNames[i].setFont(MainGUI.FONT);
            certNames[i].setEditable(false);
            components.add(certNames[i]);
            add(certNames[i], c);

            c.gridx++;

            button = new JButton("Clear");
            button.setActionCommand("clearcert" + (baseIndex + i));
            button.addActionListener(listener);
            clearButtons[i] = button;
            components.add(button);
            add(button, c);

            c.gridx++;

            button = new JButton("View");
            button.setActionCommand("viewcardcert" + (baseIndex + i));
            button.addActionListener(listener);
            components.add(button);
            viewButtons[i] = button;
            add(button, c);

            if (!ca) {
                c.gridx++;

                button = new JButton("Verify");
                button.setActionCommand("verifycert" + (baseIndex + i));
                button.addActionListener(listener);
                verifyButtons[i] = button;
                components.add(button);
                add(button, c);

                c.gridx++;

                verifyFlags[i] = new JTextField(6);
                verifyFlags[i].setFont(MainGUI.FONT);
                verifyFlags[i].setEditable(false);
                components.add(verifyFlags[i]);
                add(verifyFlags[i], c);
            }

            c.gridx++;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1;
            add(new JLabel(), c);

        }
        updateCertsStatus();
        setBorder(BorderFactory.createTitledBorder((ca ? "CA" : "User")
                + " Certificates"));

    }

    public void setEnabled(boolean flag) {
        for (JComponent c : components) {
            c.setEnabled(flag);
        }
        if (flag) {
            updateCertsStatus();
        }
    }

    public void updateCertsStatus() {
        for (int i = 0; i < totalCerts; i++) {
            boolean f = enabledCerts[i];
            certNames[i].setEnabled(f);
            clearButtons[i].setEnabled(f);
            viewButtons[i].setEnabled(f);
            if (verifyFlags != null) {
                clearVerified(baseIndex + i);
                verifyFlags[i].setEnabled(f);
                verifyButtons[i].setEnabled(f);
            }
        }

    }

    public void setCertEnabled(int num, boolean flag) {
        enabledCerts[num - baseIndex] = flag;
        updateCertsStatus();
    }

    public void setVerified(int num, boolean flag) {
        String text = null;
        Color c = null;
        if (flag) {
            c = Color.GREEN;
            text = "OK";
        } else {
            c = Color.RED;
            text = "Fail";
        }
        verifyFlags[num - baseIndex].setForeground(c);
        verifyFlags[num - baseIndex].setText(text);
    }

    public int getCACertNum() {
        return 0;
    }

    public void clearVerified(int num) {
        verifyFlags[num - baseIndex].setText("");
    }

    public void setCertName(int num, String name) {
        certNames[num - baseIndex].setText(name);
    }

}
