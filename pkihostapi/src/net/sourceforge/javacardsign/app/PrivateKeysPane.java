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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import net.sourceforge.javacardsign.service.Util;
import net.sourceforge.javacardsign.app.inputverifiers.CaretChangeListener;
import net.sourceforge.javacardsign.app.inputverifiers.HexInputVerifier;
import net.sourceforge.javacardsign.app.inputverifiers.PathInputVerifier;


public class PrivateKeysPane extends JPanel implements ActionListener {

    private Vector<JComponent> components = new Vector<JComponent>();

    private PathInputVerifier pathInputVerifier = new PathInputVerifier();

    private HexInputVerifier hexInputVerifier = new HexInputVerifier(2);

    private JTextField[] keyPaths = new JTextField[3];

    private JTextField[] keyIds = new JTextField[3];

    private static final String[] labels = new String[] { "Auth", "Sign", "Dec" };

    public PrivateKeysPane(ActionListener listener) {
        super();
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        double w = c.weightx;
        JButton button = null;

        for (int i = 0; i < 3; i++) {
            c.gridx = 0;
            c.gridy = i;
            c.weightx = w;
            c.fill = GridBagConstraints.NONE;
            c.anchor = GridBagConstraints.EAST;
            c.insets = new Insets(5, 0, 5, 10);

            add(new JLabel(labels[i] + " Key ID:"), c);
            c.gridx++;

            c.fill = GridBagConstraints.NONE;
            c.anchor = GridBagConstraints.WEST;

            keyIds[i] = new JTextField(5);
            keyIds[i].setFont(MainGUI.FONT);
            keyIds[i].setInputVerifier(hexInputVerifier);
            keyIds[i].getCaret().addChangeListener(
                    new CaretChangeListener(keyIds[i], hexInputVerifier));
            components.add(keyIds[i]);
            add(keyIds[i], c);

            c.gridx++;

            button = new JButton("Default");
            button.setActionCommand("restorekey" + i);
            button.addActionListener(listener);
            add(button, c);
            components.add(button);
            c.gridx++;

            keyPaths[i] = new JTextField(40);
            keyPaths[i].setFont(MainGUI.FONT);
            keyPaths[i].setInputVerifier(pathInputVerifier);
            keyPaths[i].getCaret().addChangeListener(
                    new CaretChangeListener(keyPaths[i], pathInputVerifier));

            components.add(keyPaths[i]);
            add(keyPaths[i], c);

            c.gridx++;

            button = new JButton("Choose File...");
            button.setActionCommand("choose" + i);
            button.addActionListener(this);
            add(button, c);
            components.add(button);

            c.gridx++;

            button = new JButton("View");
            button.setActionCommand("viewkeyfile" + i);
            button.addActionListener(listener);
            add(button, c);
            components.add(button);

            c.gridx++;

            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1;
            add(new JLabel(), c);

        }

        setBorder(BorderFactory.createTitledBorder("Private Keys"));

    }

    String getKeyPath(int num) {
        if (!pathInputVerifier.verify(keyPaths[num]))
            return null;
        return keyPaths[num].getText();
    }

    void setKeyPath(int num, String path) {
        keyPaths[num].setText(path);
    }

    byte[] getKeyId(int num) {
        if (!hexInputVerifier.verify(keyIds[num]))
            return null;
        return Util.stringToByteArray(keyIds[num].getText());
    }

    void setKeyId(int num, byte[] id) {
        keyIds[num].setText(Util.byteArrayToString(id, false));
    }

    public void setEnabled(boolean flag) {
        for (JComponent c : components) {
            c.setEnabled(flag);
        }
    }

    public void actionPerformed(ActionEvent e) {
        String command = e.getActionCommand();

        if (command.startsWith("choose")) {
            int num = MainGUI.getCommandNum("choose", command);
            File f = MainGUI.getFile(this, "Choose " + labels[num]
                    + " key file");
            if (f == null)
                return;
            keyPaths[num].setText(f.getAbsolutePath());
        }
    }

}
