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
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import net.sourceforge.javacardsign.service.Util;
import net.sourceforge.javacardsign.app.inputverifiers.CaretChangeListener;
import net.sourceforge.javacardsign.app.inputverifiers.HexInputVerifier;


public class SignaturePane extends JPanel implements ActionListener {
    private JTextArea dtbsta = null;

    private JTextArea signatureta = null;

    private JTextArea hashta = null;

    private JRadioButton authrb = null;

    private JRadioButton signrb = null;

    private JRadioButton pkcsrb = null;

    private JRadioButton pssrb = null;

    private JRadioButton sha1rb = null;

    private JRadioButton sha256rb = null;

    private JTextField verifyFlag = null;

    private JCheckBox hexcb = null;

    private Vector<JComponent> components = new Vector<JComponent>();

    private HexInputVerifier hexInputVerifier = new HexInputVerifier();

    public SignaturePane(ActionListener listener) {
        super();
        setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        double w = c.weightx;

        JPanel dtbsPanel = new JPanel();
        dtbsPanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = w;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 5, 5, 5);

        dtbsta = new JTextArea(4, 80);
        dtbsta.setInputVerifier(hexInputVerifier);
        dtbsta.getCaret().addChangeListener(
                new CaretChangeListener(dtbsta, hexInputVerifier));
        dtbsta.setEditable(true);
        dtbsta.setFont(MainGUI.FONT);
        dtbsta.setAutoscrolls(true);
        components.add(dtbsta);

        JScrollPane sp = new JScrollPane(dtbsta,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

        c.weightx = 1;

        JPanel p1 = new JPanel();
        p1.setLayout(new BorderLayout());
        p1.add(sp);

        c.gridheight = 5;
        dtbsPanel.add(p1, c);

        c.gridheight = 1;
        c.weightx = w;

        c.fill = GridBagConstraints.NONE;

        c.gridx++;

        JButton button = null;

        button = new JButton("Load...");
        button.setActionCommand("dtbsload");
        button.addActionListener(this);
        components.add(button);
        dtbsPanel.add(button, c);

        c.gridy++;
        button = new JButton("Save...");
        button.setActionCommand("dtbssave");
        button.addActionListener(this);
        components.add(button);
        dtbsPanel.add(button, c);

        c.gridy++;
        button = new JButton("Sign");
        button.setActionCommand("sign");
        button.addActionListener(listener);
        components.add(button);
        dtbsPanel.add(button, c);

        c.gridy++;
        hexcb = new JCheckBox("Hex", false);
        hexcb.setActionCommand("hex");
        hexcb.addActionListener(this);
        hexInputVerifier.setIgnore(true);

        components.add(hexcb);
        dtbsPanel.add(hexcb, c);

        c.gridy = 3;
        c.gridx = 1;
        c.gridwidth = 1;
        c.fill = GridBagConstraints.VERTICAL;
        c.weighty = 1;
        dtbsPanel.add(new JLabel(), c);

        c.gridy = 4;
        c.gridx = 0;
        c.gridwidth = 2;
        c.insets = new Insets(0, 0, 0, 0);
        c.fill = GridBagConstraints.HORIZONTAL;

        dtbsPanel
                .add(
                        new JLabel(
                                "                                                                                                                                                                          "),
                        c);

        dtbsPanel.setBorder(BorderFactory
                .createTitledBorder("Data to be signed / encrypted"));

        JPanel signaturePanel = new JPanel();
        signaturePanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 3;
        c.gridheight = 1;
        c.weighty = w;
        c.weightx = w;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 5, 5, 5);

        signatureta = new JTextArea(6, 120);
        signatureta.setEditable(false);
        signatureta.setFont(MainGUI.FONT);
        signatureta.setAutoscrolls(true);
        components.add(signatureta);

        sp = new JScrollPane(signatureta,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

        sp.setMinimumSize(new Dimension(10, 50));
        c.weightx = 1;

        p1 = new JPanel();
        p1.setLayout(new BorderLayout());
        p1.add(sp);

        signaturePanel.add(p1, c);

        c.gridwidth = 1;
        c.gridy++;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;

        button = new JButton("Save...");
        button.setActionCommand("signaturesave");
        button.addActionListener(this);
        components.add(button);
        signaturePanel.add(button, c);

        c.gridx++;
        button = new JButton("Clear");
        button.setActionCommand("clear");
        button.addActionListener(this);
        components.add(button);
        signaturePanel.add(button, c);

        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;

        c.gridx++;
        c.weightx = 10;

        signaturePanel.add(new JLabel(""), c);

        c.gridy++;
        c.gridx = 0;
        c.gridwidth = 3;
        c.insets = new Insets(0, 0, 0, 0);

        signaturePanel
                .add(
                        new JLabel(
                                "                                                                                                  "),
                        c);
        signaturePanel.setBorder(BorderFactory.createTitledBorder("Signature"));

        JPanel configPanel = new JPanel();
        configPanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.weighty = w;
        c.weightx = w;

        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 5, 5, 5);

        authrb = new JRadioButton("Auth", false);
        signrb = new JRadioButton("Sign", true);
        ButtonGroup bg1 = new ButtonGroup();
        bg1.add(authrb);
        bg1.add(signrb);
        components.add(authrb);
        components.add(signrb);

        authrb.setActionCommand("auth");
        signrb.setActionCommand("sign");
        authrb.addActionListener(this);
        signrb.addActionListener(this);

        configPanel.add(signrb, c);
        c.gridx++;
        configPanel.add(authrb, c);
        c.gridx++;
        configPanel.add(new JLabel("       "), c);

        c.gridx++;

        pkcsrb = new JRadioButton("PKCS1", true);
        pssrb = new JRadioButton("PSS", false);
        ButtonGroup bg2 = new ButtonGroup();
        bg2.add(pkcsrb);
        bg2.add(pssrb);
        components.add(pkcsrb);
        components.add(pssrb);

        pkcsrb.setActionCommand("pkcs");
        pssrb.setActionCommand("pss");
        pkcsrb.addActionListener(this);
        pssrb.addActionListener(this);

        configPanel.add(pkcsrb, c);
        c.gridx++;
        configPanel.add(pssrb, c);
        c.gridx++;
        configPanel.add(new JLabel("      "), c);

        c.gridx++;

        sha1rb = new JRadioButton("SHA1", true);
        sha256rb = new JRadioButton("SHA256", false);
        ButtonGroup bg3 = new ButtonGroup();
        bg3.add(sha1rb);
        bg3.add(sha256rb);
        components.add(sha1rb);
        components.add(sha256rb);

        configPanel.add(sha1rb, c);
        c.gridx++;
        configPanel.add(sha256rb, c);
        c.gridx++;
        configPanel.add(new JLabel("      "), c);

        c.gridx++;

        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        configPanel.add(new JLabel(""), c);

        configPanel.setBorder(BorderFactory
                .createTitledBorder("Signature Config"));

        JPanel verifyPanel = new JPanel();
        verifyPanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.weighty = w;
        c.weightx = w;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 5, 5, 5);

        button = new JButton("Verify");
        button.setActionCommand("sigverify");
        button.addActionListener(listener);
        components.add(button);
        verifyPanel.add(button, c);
        c.gridx++;

        verifyFlag = new JTextField(6);
        verifyFlag.setFont(MainGUI.FONT);
        verifyFlag.setEditable(false);
        components.add(verifyFlag);
        verifyPanel.add(verifyFlag, c);

        c.gridx++;

        c.weightx = 10;
        c.fill = GridBagConstraints.HORIZONTAL;
        verifyPanel.add(new JLabel(), c);

        verifyPanel.setBorder(BorderFactory.createTitledBorder("Verify"));

        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.weightx = w;
        c.weighty = w;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 0, 5, 0);

        add(configPanel, c);
        c.gridy++;
        add(dtbsPanel, c);
        c.gridy++;
        add(signaturePanel, c);
        c.gridy++;
        add(verifyPanel, c);

    }

    public void setHashText(String text) {
        hashta.setText(text);
    }

    public String getHashText() {
        return hashta.getText();
    }

    public String getDTBSText() {
        return dtbsta.getText();
    }

    public void setDTBSText(String t) {
        dtbsta.setText(t);
    }

    public boolean getHex() {
        return hexcb.isSelected();
    }

    public void setHex(boolean flag) {
        hexcb.setSelected(flag);
        if (flag)
            hexInputVerifier.setIgnore(false);
    }

    public void setSignatureText(String text) {
        signatureta.setText(text);
        clearVerified();
    }

    public String getSignatureText() {
        return signatureta.getText();
    }

    public boolean getAuth() {
        return authrb.isSelected();
    }

    public boolean getPKCS() {
        return pkcsrb.isSelected();
    }

    public boolean getSHA1() {
        return sha1rb.isSelected();
    }

    public void setVerified(boolean flag) {
        String text = null;
        Color c = null;
        if (flag) {
            c = Color.GREEN;
            text = "OK";
        } else {
            c = Color.RED;
            text = "Fail";
        }
        verifyFlag.setForeground(c);
        verifyFlag.setText(text);
    }

    private void clearVerified() {
        verifyFlag.setForeground(Color.BLACK);
        verifyFlag.setText("");
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("signaturesave")) {
            MainGUI.saveFile(this, "Save Signature", signatureta.getText());
        }
        if (e.getActionCommand().equals("dtbssave")) {
            MainGUI.saveFile(this, "Save DTBS", dtbsta.getText());
        }

        if (e.getActionCommand().equals("dtbsload")) {
            String t = MainGUI.openFile(this, "Open DTBS file");
            if (t != null) {
                if (hexcb.isSelected()) {
                    t = Util.byteArrayToString(t.getBytes(), false, 30);
                }
                dtbsta.setText(t);
            }

        }

        if (e.getActionCommand().equals("hashload")) {
            String t = MainGUI.openFile(this, "Open Hash");
            if (t != null) {
                hashta.setText(t);
            }

        }

        if (e.getActionCommand().equals("hashsave")) {
            MainGUI.saveFile(this, "Save Hash", hashta.getText());
        }

        if (e.getActionCommand().equals("clear")) {
            signatureta.setText("");
            clearVerified();
        }
        if (e.getActionCommand().equals("auth")) {
            pkcsrb.setSelected(true);
            pkcsrb.setEnabled(false);
            pssrb.setEnabled(false);
            sha1rb.setEnabled(false);
            sha256rb.setEnabled(false);
        }
        if (e.getActionCommand().equals("sign")) {
            pkcsrb.setEnabled(true);
            pssrb.setEnabled(true);
            sha1rb.setEnabled(true);
            sha256rb.setEnabled(true);
        }
        if (e.getActionCommand().equals("pkcs")) {
            sha1rb.setEnabled(true);
            sha256rb.setEnabled(true);
        }
        if (e.getActionCommand().equals("pss")) {
            sha1rb.setSelected(true);
            sha1rb.setEnabled(false);
            sha256rb.setEnabled(false);
        }
        if (e.getActionCommand().equals("hex")) {
            hexInputVerifier.setIgnore(!hexcb.isSelected());
            hexInputVerifier.verify(dtbsta);
        }
    }

    public void setEnabled(boolean flag) {
        for (JComponent c : components) {
            c.setEnabled(flag);
        }
        if (flag) {
            sha1rb.setEnabled(!pssrb.isSelected());
            sha256rb.setEnabled(!pssrb.isSelected());
            pkcsrb.setEnabled(signrb.isSelected());
            pssrb.setEnabled(signrb.isSelected());
            sha1rb.setEnabled(signrb.isSelected());
            sha256rb.setEnabled(signrb.isSelected());
        }
    }

}
