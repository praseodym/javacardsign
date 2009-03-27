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
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextField;

import net.sourceforge.javacardsign.service.Util;
import net.sourceforge.javacardsign.app.inputverifiers.CaretChangeListener;
import net.sourceforge.javacardsign.app.inputverifiers.HexInputVerifier;
import net.sourceforge.javacardsign.app.inputverifiers.PINInputVerifier;


public class PrivateInitPanel extends JPanel {

    private JTextField histBytes = null;

    private JTextField pucField = null;

    private PrivateKeysPane pkp = null;

    private CertificatesPane cp = null;

    private Vector<JComponent> components = new Vector<JComponent>();

    private HexInputVerifier hexInputVerifier = new HexInputVerifier();

    private PINInputVerifier pucInputVerifier = new PINInputVerifier(16, 16);

    public PrivateInitPanel(ActionListener listener) {
        super();

        JPanel histPanel = new JPanel();
        histPanel.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 0, 5, 20);

        c.gridx++;

        histBytes = new JTextField(30);
        histBytes.setFont(MainGUI.FONT);
        histBytes.setInputVerifier(hexInputVerifier);
        histBytes.getCaret().addChangeListener(
                new CaretChangeListener(histBytes, hexInputVerifier));

        components.add(histBytes);
        histPanel.add(histBytes, c);

        JButton button = new JButton("Set Historical Bytes");
        button.setActionCommand("sethist");
        button.addActionListener(listener);
        components.add(button);
        c.gridx++;
        c.weightx = 1;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;
        histPanel.add(button, c);

        histPanel.setBorder(BorderFactory
                .createTitledBorder("Historical Bytes"));

        c = new GridBagConstraints();
        JPanel pucPanel = new JPanel();
        pucPanel.setLayout(new GridBagLayout());
        c.gridx = 0;
        c.gridy = 0;

        pucField = new JTextField(19);
        pucField.setFont(MainGUI.FONT);
        pucField.setInputVerifier(pucInputVerifier);
        pucField.getCaret().addChangeListener(
                new CaretChangeListener(pucField, pucInputVerifier));
        components.add(pucField);
        pucPanel.add(pucField, c);

        c.gridx++;
        c.weightx = 1;

        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 10, 5, 20);
        button = new JButton("Default");
        button.setActionCommand("restorepuc");
        button.addActionListener(listener);
        components.add(button);
        pucPanel.add(button, c);

        pucPanel.setBorder(BorderFactory.createTitledBorder("PUC"));

        setLayout(new GridBagLayout());
        GridBagConstraints cc = new GridBagConstraints();
        cc.gridx = 0;
        cc.gridy = 0;
        cc.fill = GridBagConstraints.HORIZONTAL;
        add(histPanel, cc);
        cc.gridy++;
        add(pucPanel, cc);
        cc.gridy++;
        pkp = new PrivateKeysPane(listener);
        components.add(pkp);
        add(pkp, cc);
        cc.gridy++;
        cp = new CertificatesPane(listener);
        components.add(cp);
        add(cp, cc);

        cc.gridy++;
        cc.gridx = 0;
        cc.fill = GridBagConstraints.HORIZONTAL;
        cc.insets = new Insets(5, 0, 5, 0);
        add(new JSeparator(), cc);
        cc.gridy++;
        cc.gridx = 0;
        cc.insets = new Insets(0, 0, 0, 0);
        cc.fill = GridBagConstraints.NONE;
        cc.anchor = GridBagConstraints.WEST;
        button = new JButton("Initialize Applet");
        button.setActionCommand("init");
        button.addActionListener(listener);
        components.add(button);
        add(button, cc);
    }

    public byte[] getHistoricalBytes() {
        if (!hexInputVerifier.verify(histBytes))
            return null;
        return Util.stringToByteArray(histBytes.getText());
    }

    public void setHistoricalBytes(byte[] bytes) {
        histBytes.setText(Util.byteArrayToString(bytes, true));
    }

    public String getPUC() {
        if (!pucInputVerifier.verify(pucField))
            return null;
        return pucField.getText();
    }

    public void setPUC(String puc) {
        pucField.setText(puc);
    }

    public PrivateKeysPane getPrivateKeyPane() {
        return pkp;
    }

    public CertificatesPane getCertificatesPane() {
        return cp;
    }

    public void setEnabled(boolean flag) {
        for (JComponent c : components) {
            c.setEnabled(flag);
        }
    }

}
