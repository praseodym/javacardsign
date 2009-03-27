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
import javax.swing.JTextField;

import net.sourceforge.javacardsign.app.inputverifiers.*;


public class ChallengePane extends JPanel implements ActionListener {
    private Vector<JComponent> components = new Vector<JComponent>();

    private JTextArea cta = null;

    private JTextField len = null;

    private IntInputVerifier intInputVerifier = new IntInputVerifier(1, 256);

    public ChallengePane(ActionListener listener) {
        super();
        setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        double w = c.weightx;

        JPanel cPanel = new JPanel();
        cPanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 6;
        c.gridheight = 1;
        c.weighty = w;
        c.weightx = w;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 5, 5, 5);

        cta = new JTextArea(6, 120);
        cta.setEditable(false);
        cta.setFont(MainGUI.FONT);
        cta.setAutoscrolls(true);
        components.add(cta);

        JScrollPane sp = new JScrollPane(cta,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

        sp.setMinimumSize(new Dimension(10, 80));
        c.weightx = 1;

        JPanel p1 = new JPanel();
        p1.setLayout(new BorderLayout());
        p1.add(sp);

        cPanel.add(p1, c);

        c.gridwidth = 1;
        c.gridy++;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;

        cPanel.add(new JLabel("Length: "), c);
        c.gridx++;
        len = new JTextField(6);
        len.setText("8");
        len.setInputVerifier(intInputVerifier);
        len.getCaret().addChangeListener(
                new CaretChangeListener(len, intInputVerifier));
        components.add(len);
        cPanel.add(len, c);
        c.gridx++;

        JButton button = new JButton("Get Challenge");
        button.setActionCommand("getchallenge");
        button.addActionListener(listener);
        components.add(button);
        cPanel.add(button, c);

        c.gridx++;
        button = new JButton("Save...");
        button.setActionCommand("save");
        button.addActionListener(this);
        components.add(button);
        cPanel.add(button, c);

        c.gridx++;
        button = new JButton("Use as DTBS");
        button.setActionCommand("usedtbs");
        button.addActionListener(listener);
        components.add(button);
        cPanel.add(button, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;

        c.gridx++;
        c.weightx = 10;

        cPanel.add(new JLabel(""), c);

        c.gridy++;
        c.gridx = 0;
        c.gridwidth = 6;
        c.insets = new Insets(0, 0, 0, 0);

        cPanel
                .add(
                        new JLabel(
                                "                                                                                                  "),
                        c);
        cPanel.setBorder(BorderFactory.createTitledBorder("Get Challenge"));

        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.weightx = w;
        c.weighty = w;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 0, 5, 0);

        add(cPanel, c);

    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("save")) {
            MainGUI.saveFile(this, "Save Challenge", cta.getText());
        }
    }

    public void setEnabled(boolean flag) {
        for (JComponent c : components) {
            c.setEnabled(flag);
        }
    }

    public void setChallenge(String c) {
        cta.setText(c);
    }

    public String getChallenge() {
        return cta.getText();
    }

    public int getLength() {
        if (intInputVerifier.verify(len)) {
            int num = 0;
            try {
                num = Integer.parseInt(len.getText());
            } catch (NumberFormatException nfe) {

            }
            return num;
        }
        return -1;
    }

}
