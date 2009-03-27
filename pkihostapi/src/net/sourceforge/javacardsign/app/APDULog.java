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

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import net.sourceforge.javacardsign.service.*;


public class APDULog extends JPanel implements ActionListener {
    private JTextArea text = null;

    private JLabel status = null;

    private JButton saveButton = null;

    public APDULog() {
        super();
        GridBagConstraints c = new GridBagConstraints();
        setLayout(new GridBagLayout());
        text = new JTextArea(10, 100);
        text.setEditable(true);
        text.setEnabled(true);
        text.setFont(MainGUI.FONT);
        text.setAutoscrolls(true);

        JScrollPane sp = new JScrollPane(text,
                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 4;
        c.fill = GridBagConstraints.BOTH;

        JPanel p = new JPanel(new BorderLayout());
        sp.setMinimumSize(new Dimension(780, 150));
        p.add(sp);

        add(p, c);

        c.gridwidth = 1;
        c.gridx = 0;
        c.gridy = 1;

        c.insets = new Insets(5, 0, 5, 5);
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.WEST;

        saveButton = new JButton("Save Log...");
        saveButton.setActionCommand("save");
        saveButton.addActionListener(this);
        add(saveButton, c);

        c.gridx++;
        c.insets = new Insets(5, 40, 5, 5);
        add(new JLabel("Status: "), c);
        status = new JLabel();
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx++;
        add(status, c);

        setBorder(BorderFactory.createTitledBorder("APDU Logger"));

    }

    public void logCommand(byte[] apdu) {
        text.append("Command APDU: " + Util.byteArrayToString(apdu, true)
                + "\n");
        status.setText("");
    }

    public void logResponse(byte[] apdu, boolean success) {
        text.append("Response APDU: " + Util.byteArrayToString(apdu, true)
                + "\n\n");
        if (success) {
            status.setText("Success: " + decodeSW(apdu));
            status.setForeground(Color.GREEN);
        } else {
            String m = decodeSW(apdu);
            status.setText("Fail: " + m);
            status.setForeground(Color.RED);
        }
    }

    public void log(String s) {
        text.append(s + "\n\n");
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("save")) {
            MainGUI.saveFile(this, "Save", text.getText());
        }
    }

    public static String decodeSW(byte[] apdu) {
        if (apdu == null || apdu.length < 2)
            return "Unknown";
        if (apdu[apdu.length - 2] == 0x6c) {
            int num = apdu[apdu.length - 1] & 0xff;
            return "Le incorrect"
                    + (num > 0 ? ": " + num + " bytes available" : "");
        }
        int sw = ((apdu[apdu.length - 2] & 0xFF) << 8)
                + (apdu[apdu.length - 1] & 0xff);
        switch (sw) {
        case 0x9000:
            return "Status OK";
        case 0x6282:
            return "End of file";
        case 0x6882:
            return "Secure messaging not supported";
        case 0x6982:
            return "Security status not satisfied";
        case 0x6986:
            return "No EF selected";
        case 0x6A82:
            return "No SFI found in current DF / file not found";
        case 0x6A86:
            return "Incorrect P1/P2";
        case 0x6E00:
            return "Invalid CLA";
        case 0x6700:
            return "Wrong length";
        case 0x6A80:
            return "Wrong data";
        case 0x6300:
            return "PIN verification failed";
        case 0x6983:
            return "PIN / PUC blocked";
        case 0x6D00:
            return "INS not supported";
        case 0x6985:
            return "Conditions not satisfied";
        case 0x6A88:
            return "Key not found / selected";
        case 0x6A81:
            return "Algorithm not supported";
        case 0x6883:
            return "Last command expected";
        case 0x6984:
            return "Wrong key use";

        default:
            return "Unknown";

        }
    }
}
