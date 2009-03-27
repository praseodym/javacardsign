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
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class ViewWindow extends JDialog implements ActionListener {

    private JTextArea ta = null;

    public ViewWindow(JFrame parent, String title, String contents) {
        super();
        setTitle(title);
        setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();

        // ta = new JTextArea(100, 100);
        // ta.setText(contents);
        ta = new JTextArea(contents);
        ta.setFont(MainGUI.FONT);
        ta.setEditable(false);

        JScrollPane sp = new JScrollPane(ta,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

        sp.setMinimumSize(new Dimension(400, 300));
        c.gridx = 0;
        c.gridwidth = 2;
        c.gridy = 0;
        c.fill = GridBagConstraints.BOTH;
        add(sp, c);

        c.gridwidth = 1;
        c.gridy++;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(5, 0, 5, 20);

        JButton button = new JButton("Save...");
        button.setActionCommand("save");
        button.addActionListener(this);
        add(button, c);

        c.gridx++;

        button = new JButton("Close");
        button.setActionCommand("close");
        button.addActionListener(this);
        add(button, c);

        setSize(new Dimension(420, 400));
        setResizable(false);
        setLocationRelativeTo(parent);
        setVisible(true);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("save")) {
            MainGUI.saveFile(this, "Save", ta.getText());

        }
        if (e.getActionCommand().equals("close")) {
            dispose();
        }

    }

}
