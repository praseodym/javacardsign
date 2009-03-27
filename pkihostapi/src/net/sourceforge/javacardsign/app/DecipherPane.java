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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import net.sourceforge.javacardsign.app.inputverifiers.*;


public class DecipherPane extends JPanel implements ActionListener {

    private JTextArea cipherta = null;

    private JTextArea decipherta = null;

    private Vector<JComponent> components = new Vector<JComponent>();

    private HexInputVerifier hexInputVerifier = new HexInputVerifier();

    public DecipherPane(ActionListener listener) {
        super();
        setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        double w = c.weightx;

        JPanel cipherPanel = new JPanel();
        cipherPanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = w;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 5, 5, 5);

        cipherta = new JTextArea(10, 80);
        cipherta.setInputVerifier(hexInputVerifier);
        cipherta.getCaret().addChangeListener(
                new CaretChangeListener(cipherta, hexInputVerifier));
        cipherta.setEditable(true);
        cipherta.setFont(MainGUI.FONT);
        cipherta.setAutoscrolls(true);
        components.add(cipherta);

        JScrollPane sp = new JScrollPane(cipherta,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

        c.weightx = 1;

        JPanel p1 = new JPanel();
        p1.setLayout(new BorderLayout());
        p1.add(sp);

        c.gridheight = 6;
        cipherPanel.add(p1, c);

        c.gridheight = 1;
        c.weightx = w;

        c.fill = GridBagConstraints.NONE;

        c.gridx++;

        JButton button = null;
        button = new JButton("Load...");
        button.setActionCommand("cipherload");
        button.addActionListener(this);
        components.add(button);
        cipherPanel.add(button, c);

        c.gridy++;
        button = new JButton("Save...");
        button.setActionCommand("ciphersave");
        button.addActionListener(this);
        components.add(button);
        cipherPanel.add(button, c);

        c.gridy++;
        button = new JButton("Encrypt Text...");
        button.setActionCommand("enctext");
        button.addActionListener(listener);
        components.add(button);
        cipherPanel.add(button, c);

        c.gridy++;
        button = new JButton("Encrypt File...");
        button.setActionCommand("encfile");
        button.addActionListener(listener);
        components.add(button);
        cipherPanel.add(button, c);

        c.gridy++;
        button = new JButton("Decrypt");
        button.setActionCommand("decrypt");
        button.addActionListener(listener);
        components.add(button);
        cipherPanel.add(button, c);

        c.gridy = 5;
        c.gridx = 1;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.VERTICAL;
        c.weighty = 1;
        cipherPanel.add(new JLabel(), c);

        c.gridy = 6;
        c.gridx = 0;
        c.gridwidth = 3;
        c.insets = new Insets(0, 0, 0, 0);
        c.fill = GridBagConstraints.HORIZONTAL;

        cipherPanel
                .add(
                        new JLabel(
                                "                                                                                                                                            "),
                        c);

        cipherPanel.setBorder(BorderFactory.createTitledBorder("Cipher Text"));

        JPanel decipherPanel = new JPanel();
        decipherPanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 3;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 5, 5, 5);

        decipherta = new JTextArea(10, 120);
        decipherta.setEditable(false);
        decipherta.setFont(MainGUI.FONT);
        decipherta.setAutoscrolls(true);
        components.add(decipherta);

        sp = new JScrollPane(decipherta, JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

        sp.setMinimumSize(new Dimension(10, 200));
        c.weightx = 1;

        p1 = new JPanel();
        p1.setLayout(new BorderLayout());
        p1.add(sp);

        decipherPanel.add(p1, c);

        c.gridwidth = 1;
        c.gridy++;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;

        button = new JButton("Save...");
        button.setActionCommand("deciphersave");
        button.addActionListener(this);
        components.add(button);
        decipherPanel.add(button, c);

        c.gridx++;
        button = new JButton("Clear");
        button.setActionCommand("clear");
        button.addActionListener(this);
        components.add(button);
        decipherPanel.add(button, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;

        c.gridx++;
        c.weightx = 10;

        decipherPanel.add(new JLabel(""), c);

        c.gridy++;
        c.gridx = 0;
        c.gridwidth = 3;
        c.insets = new Insets(0, 0, 0, 0);

        decipherPanel
                .add(
                        new JLabel(
                                "                                                                                                  "),
                        c);
        decipherPanel.setBorder(BorderFactory.createTitledBorder("Result"));

        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.weightx = w;
        c.weighty = w;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 0, 5, 0);

        add(cipherPanel, c);
        c.gridy++;
        add(decipherPanel, c);

    }

    public void setCipherText(String text) {
        cipherta.setText(text);
    }

    public String getCipherText() {
        return cipherta.getText();
    }

    public void setDecipherText(String text) {
        decipherta.setText(text);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("deciphersave")) {
            MainGUI.saveFile(this, "Save Decipher", decipherta.getText());
        }
        if (e.getActionCommand().equals("ciphersave")) {
            MainGUI.saveFile(this, "Save Cipher", cipherta.getText());
        }

        if (e.getActionCommand().equals("cipherload")) {
            String t = MainGUI.openFile(this, "Open file");
            if (t != null)
                cipherta.setText(t);

        }

        if (e.getActionCommand().equals("clear")) {
            decipherta.setText("");
        }

    }

    public void setEnabled(boolean flag) {
        for (JComponent c : components) {
            c.setEnabled(flag);
        }
    }

}
