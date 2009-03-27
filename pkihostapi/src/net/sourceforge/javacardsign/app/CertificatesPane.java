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

import net.sourceforge.javacardsign.app.inputverifiers.*;


public class CertificatesPane extends JPanel implements ActionListener {

    private Vector<JComponent> components = new Vector<JComponent>();

    private PathInputVerifier pathInputVerifier = new PathInputVerifier();

    private static final String[] labels = { "User Auth Cert",
            "User Sign Cert", "User Dec Cert", "CA Cert" };

    private JTextField[] pathFields = new JTextField[6];

    public CertificatesPane(ActionListener listener) {
        super();
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        double w = c.weightx;

        c.insets = new Insets(5, 0, 5, 10);
        JButton button = null;

        for (int i = 0; i < labels.length; i++) {
            c.gridx = 0;
            c.gridy = i;
            c.weightx = w;
            c.fill = GridBagConstraints.NONE;
            c.anchor = GridBagConstraints.EAST;
            add(new JLabel(labels[i] + ":"), c);

            c.anchor = GridBagConstraints.WEST;
            c.gridx++;

            pathFields[i] = new JTextField(40);
            pathFields[i].setFont(MainGUI.FONT);
            pathFields[i].setInputVerifier(pathInputVerifier);
            pathFields[i].getCaret().addChangeListener(
                    new CaretChangeListener(pathFields[i], pathInputVerifier));
            components.add(pathFields[i]);
            add(pathFields[i], c);

            c.gridx++;

            button = new JButton("Choose file...");
            button.setActionCommand("choose" + i);
            button.addActionListener(this);
            components.add(button);
            add(button, c);

            c.gridx++;

            button = new JButton("View");
            button.setActionCommand("viewcert" + i);
            button.addActionListener(listener);
            components.add(button);
            add(button, c);

            c.gridx++;

            button = new JButton("Default");
            button.setActionCommand("restorecert" + i);
            button.addActionListener(listener);
            components.add(button);
            add(button, c);

            c.gridx++;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.weightx = 1;
            add(new JLabel(), c);
        }

        setBorder(BorderFactory.createTitledBorder("Certificates"));

    }

    void setPath(int num, String path) {
        pathFields[num].setText(path);
    }

    String getPath(int num) {
        if (!pathInputVerifier.verify(pathFields[num])) {
            return null;
        }
        return pathFields[num].getText();
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
            File f = MainGUI.getFile(this, "Choose " + labels[num] + " file");
            if (f == null)
                return;
            pathFields[num].setText(f.getAbsolutePath());
        }

    }

}
