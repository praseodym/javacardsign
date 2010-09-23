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
import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Vector;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import net.sourceforge.javacardsign.service.*;

import net.sourceforge.scuba.smartcards.APDUEvent;
import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardEvent;
import net.sourceforge.scuba.smartcards.CardManager;
import net.sourceforge.scuba.smartcards.CardServiceException;

public class MainGUI extends JFrame implements ActionListener, APDUListener,
        PKIAppletListener {

    public static final Font FONT = new Font("Monospaced", Font.PLAIN, 12);

    private PKIPersoService service = null;

    private APDULog apduLog = null;

    private PrivateInitPanel pi = null;

    private CardCertificatesPane caCertsPane = null;

    private CardCertificatesPane userCertsPane = null;

    private UserAdministrationPane adminPane = null;

    private DecipherPane decPane = null;

    private SignaturePane sigPane = null;

    private ChallengePane chalPane = null;

    private Vector<JComponent> components = new Vector<JComponent>();

    private X509Certificate[] certificates = new X509Certificate[6];

    public MainGUI() {
        setTitle("PKI Sample GUI Host");
        setLayout(new BorderLayout());

        JTabbedPane tabbedPane = new JTabbedPane();

        pi = new PrivateInitPanel(this);
        pi.setHistoricalBytes(new byte[0]);
        pi.setPUC(PKIPersoService.DEFAULT_PUC);
        pi.getPrivateKeyPane().setKeyPath(0, TestKeys.authkeyFileName);
        pi.getPrivateKeyPane().setKeyId(0, TestKeys.AUTH_KEY_ID);
        pi.getPrivateKeyPane().setKeyPath(1, TestKeys.signkeyFileName);
        pi.getPrivateKeyPane().setKeyId(1, TestKeys.SIGN_KEY_ID);
        pi.getPrivateKeyPane().setKeyPath(2, TestKeys.deckeyFileName);
        pi.getPrivateKeyPane().setKeyId(2, TestKeys.DEC_KEY_ID);

        pi.getCertificatesPane().setPath(0, TestKeys.authcertFileName);
        pi.getCertificatesPane().setPath(1, TestKeys.signcertFileName);
        pi.getCertificatesPane().setPath(2, TestKeys.deccertFileName);
        pi.getCertificatesPane().setPath(3, TestKeys.cacertFileName);

        components.add(pi);
        tabbedPane.add("Private Init", pi);

        adminPane = new UserAdministrationPane(this);
        components.add(adminPane);
        tabbedPane.add("User Administration", adminPane);

        JPanel certPanel = new JPanel();
        certPanel.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();

        c.fill = GridBagConstraints.HORIZONTAL;

        caCertsPane = new CardCertificatesPane(true, this);
        userCertsPane = new CardCertificatesPane(false, this);
        c.gridx = 0;
        c.gridy = 0;
        c.insets = new Insets(5, 0, 5, 0);
        components.add(caCertsPane);
        certPanel.add(caCertsPane, c);
        c.gridy++;
        components.add(userCertsPane);
        certPanel.add(userCertsPane, c);

        tabbedPane.add("Certificates", certPanel);

        decPane = new DecipherPane(this);
        components.add(decPane);
        tabbedPane.add("Decrypt", decPane);

        sigPane = new SignaturePane(this);
        components.add(sigPane);
        tabbedPane.add("Signature & Authentication", sigPane);

        chalPane = new ChallengePane(this);
        components.add(chalPane);
        tabbedPane.add("Challenge", chalPane);

        add(tabbedPane, BorderLayout.CENTER);

        components.add(tabbedPane);

        apduLog = new APDULog();
        add(apduLog, BorderLayout.SOUTH);
        setSize(900, 950);
        setResizable(false);
        setEnabled(false);
        setVisible(true);
        addWindowListener(new WindowListener() {

            public void windowActivated(WindowEvent e) {
            }

            public void windowClosed(WindowEvent e) {
            }

            public void windowClosing(WindowEvent e) {
                System.out.println("Exiting...");
                System.exit(0);
            }

            public void windowDeactivated(WindowEvent e) {
            }

            public void windowDeiconified(WindowEvent e) {
            }

            public void windowIconified(WindowEvent e) {
            }

            public void windowOpened(WindowEvent e) {
            }

        });
    }

    public void setEnabled(boolean flag) {
        for (JComponent c : components) {
            c.setEnabled(flag);
        }

    }

    void actionInitialize() throws CardServiceException {
        byte[] authKeyId = pi.getPrivateKeyPane().getKeyId(0);
        byte[] signKeyId = pi.getPrivateKeyPane().getKeyId(1);
        byte[] decKeyId = pi.getPrivateKeyPane().getKeyId(2);
        String authKeyPath = pi.getPrivateKeyPane().getKeyPath(0);
        String signKeyPath = pi.getPrivateKeyPane().getKeyPath(1);
        String decKeyPath = pi.getPrivateKeyPane().getKeyPath(2);
        if (authKeyId == null || signKeyId == null || decKeyId == null
                || authKeyPath == null || signKeyPath == null
                || decKeyPath == null) {
            return;
        }
        RSAPrivateCrtKey authKey = (RSAPrivateCrtKey) CryptoUtils
                .readPrivateKeyFromDER(authKeyPath);
        RSAPrivateCrtKey signKey = (RSAPrivateCrtKey) CryptoUtils
                .readPrivateKeyFromDER(signKeyPath);
        RSAPrivateCrtKey decKey = (RSAPrivateCrtKey) CryptoUtils
                .readPrivateKeyFromDER(decKeyPath);
        if (authKey == null) {
            apduLog.log("Invalid auth key file.");

        } else if (signKey == null) {
            apduLog.log("Invalid sign key file.");

        } else if (decKey == null) {
            apduLog.log("Invalid dec key file.");

        }
        X509Certificate[] certs = new X509Certificate[4];
        for (int i = 0; i < 4; i++) {
            String fileName = pi.getCertificatesPane().getPath(i);
            if (fileName == null) {
                return;
            }
            X509Certificate cert = CryptoUtils.readCertFromDER(fileName);
            if (cert == null) {
                apduLog.log("Invalid certificate file \"" + fileName + "\".");
                return;
            }
            certs[i] = cert;
        }
        service.initializeApplet(certs[3], certs[0], certs[1], certs[2],
                authKey, signKey, decKey, authKeyId, signKeyId, decKeyId, pi
                        .getPUC());
    }

    void actionViewKey(int num) {
        String fileName = pi.getPrivateKeyPane().getKeyPath(num);
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) CryptoUtils
                .readPrivateKeyFromDER(fileName);
        new ViewWindow(this, "Key view", "" + key);
    }

    void actionViewCert(int num) {
        String fileName = pi.getCertificatesPane().getPath(num);
        X509Certificate cert = CryptoUtils.readCertFromDER(fileName);
        new ViewWindow(this, "Certificate view", "" + cert);
    }

    void actionRestoreKey(int num) {
        String fileName = null;
        byte[] keyId = null;
        if (num == 0) {
            fileName = TestKeys.authkeyFileName;
            keyId = TestKeys.AUTH_KEY_ID;
        } else if (num == 1) {
            fileName = TestKeys.signkeyFileName;
            keyId = TestKeys.SIGN_KEY_ID;
        } else if (num == 2) {
            fileName = TestKeys.deckeyFileName;
            keyId = TestKeys.DEC_KEY_ID;
        }
        pi.getPrivateKeyPane().setKeyPath(num, fileName);
        pi.getPrivateKeyPane().setKeyId(num, keyId);
    }

    void actionRestoreCert(int num) {
        String fileName = null;
        if (num == 0) {
            fileName = TestKeys.authcertFileName;
        } else if (num == 1) {
            fileName = TestKeys.signcertFileName;
        } else if (num == 2) {
            fileName = TestKeys.deccertFileName;
        } else if (num == 3) {
            fileName = TestKeys.cacertFileName;
        } else {
            fileName = "<NONE>";
        }
        pi.getCertificatesPane().setPath(num, fileName);

    }

    void actionCardGetCert(int num) throws CardServiceException {
        short id = 0;
        if (num == 0) {
            id = 0x4101;
        } else if (num == 3) {
            id = 0x4102;
        } else if (num == 4) {
            id = 0x4103;
        } else if (num == 5) {
            id = 0x4104;
        }

        byte[] cert = null;
        try {
            cert = service.readFile(id);
        } catch (CardServiceException jce) {
            // Try with PIN
            PINEnterDialog pe = new PINEnterDialog(this, "Enter PIN", 4, 20);
            char[] pin = pe.getPIN();
            if (pin != null && pin.length != 0) {
                byte[] p = new byte[pin.length];
                for (int i = 0; i < p.length; i++)
                    p[i] = (byte) pin[i];
                cert = service.readFile(id, p);
            }
        }
        int len = 0;
        if (cert.length >= 4) {
            len = (cert[2] << 8) + (cert[3] & 0xFF) + 4;
        }
        byte[] t = new byte[len];
        System.arraycopy(cert, 0, t, 0, len);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate c = (X509Certificate) cf
                    .generateCertificate(new ByteArrayInputStream(t));
            certificates[num] = c;
            String name = certificates[num].getSubjectDN().getName();
            if (num < 3) {
                caCertsPane.setCertEnabled(num, true);
                caCertsPane.setCertName(num, name);
            } else {
                userCertsPane.setCertEnabled(num, true);
                userCertsPane.setCertName(num, name);
                userCertsPane.clearVerified(num);
            }

        } catch (Exception ex) {
            apduLog.log("Corrupted certificate: "
                    + Util.byteArrayToString(cert, false));
        }
    }

    void actionLoadCert(int num) {
        String[] labels = { "CA Cert1", "CA Cert2", "CA Cert3",
                "User Auth Cert", "User Sign Cert", "User Dec Cert" };

        File f = getFile(this, "Open " + labels[num]);
        if (f == null)
            return;
        certificates[num] = CryptoUtils.readCertFromDER(f.getAbsolutePath());
        String name = certificates[num].getSubjectDN().getName();
        if (num < 3) {
            caCertsPane.setCertEnabled(num, true);
            caCertsPane.setCertName(num, name);
        } else {
            userCertsPane.setCertEnabled(num, true);
            userCertsPane.setCertName(num, name);
            userCertsPane.clearVerified(num);
        }
        try {
        } catch (Exception ex) {
            apduLog.log("Could not save file \"" + f.getName() + "\"");

        }
    }

    void actionClearCert(int num) {
        certificates[num] = null;
        if (num < 3) {
            caCertsPane.setCertEnabled(num, false);
            caCertsPane.setCertName(num, "");
        } else {
            userCertsPane.setCertEnabled(num, false);
            userCertsPane.setCertName(num, "");
            userCertsPane.clearVerified(num);
        }

    }

    void actionVerifyCert(int num) {
        X509Certificate c = certificates[num];
        X509Certificate cacert = certificates[caCertsPane.getCACertNum()];
        if (cacert == null) {
            userCertsPane.clearVerified(num);
            apduLog.log("No loaded CA certificate selected.");
            return;
        }
        try {
            c.verify(cacert.getPublicKey());
            userCertsPane.setVerified(num, true);
        } catch (SignatureException se) {
            userCertsPane.setVerified(num, false);
        } catch (Exception ex) {
            userCertsPane.clearVerified(num);
            apduLog.log("Verification of signature failed.");
        }

    }

    void actionSetPIN() throws CardServiceException {
        char[] p1 = adminPane.getPIN1();
        char[] p2 = adminPane.getPIN2();
        if (!new String(p1).equals(new String(p2))) {
            JOptionPane.showMessageDialog(this, "The two PINs do not match!");
            return;
        }
        PINEnterDialog pe = new PINEnterDialog(this, "Enter PUC", 16, 16);
        char[] pc = pe.getPIN();
        if (pc != null && pc.length != 0 && p1.length != 0) {
            byte[] pin = new byte[p1.length];
            byte[] puc = new byte[pc.length];
            for (int i = 0; i < pin.length; i++) {
                pin[i] = (byte) p1[i];
            }
            for (int i = 0; i < puc.length; i++) {
                puc[i] = (byte) pc[i];
            }
            service.changePIN(puc, pin);
            adminPane.clearPIN12();
        }
    }

    void actionVerifyPIN() throws CardServiceException {
        char[] p = adminPane.getPIN3();
        if (p != null && p.length != 0) {
            byte[] pin = new byte[p.length];
            for (int i = 0; i < pin.length; i++) {
                pin[i] = (byte) p[i];
            }
            service.verifyPIN(pin);
            adminPane.clearPIN3();
        }
    }

    void actionEncFile() {
        if (certificates[5] == null) {
            apduLog.log("No User Decipher Certificate loaded.");
            return;
        }
        String inData = openFile(this, "Open file");
        if (inData == null) {
            return;
        }
        if (inData.length() > 117) {
            JOptionPane.showMessageDialog(this, "File too long.");
            return;

        }

        byte[] data = inData.getBytes();
        byte[] out = CryptoUtils.pkcs1Encrypt(certificates[5].getPublicKey(),
                data);
        decPane.setCipherText(Util.byteArrayToString(out, false, 20));
    }

    void actionDecrypt() throws CardServiceException {
        byte[] data = Util.stringToByteArray(decPane.getCipherText());
        if (data == null)
            return;
        byte[] keyId = pi.getPrivateKeyPane().getKeyId(2);
        if (keyId == null)
            return;
        PINEnterDialog pe = new PINEnterDialog(this, "Enter PIN", 4, 20);
        char[] c = pe.getPIN();
        if (c == null)
            return;

        // manage secure environment, pin
        byte[] p = new byte[c.length];
        for (int i = 0; i < p.length; i++) {
            p[i] = (byte) c[i];
        }
        service.manageSecurityEnvironment(PKIService.MSE_DEC, keyId, (byte) 1);
        service.verifyPIN(p);

        byte[] result = service.decipher(data, 255);
        decPane.setDecipherText(new String(result));
    }

    void actionEncText() {
        if (certificates[5] == null) {
            apduLog.log("No User Decipher Certificate loaded.");
            return;
        }
        EditWindow ew = new EditWindow(this, "Enter Text...");
        String text = ew.getEditText();
        if (text == null)
            return;
        if (text.length() > 117) {
            JOptionPane.showMessageDialog(this, "Text too long.");
            return;

        }

        byte[] data = text.getBytes();
        byte[] out = CryptoUtils.pkcs1Encrypt(certificates[5].getPublicKey(),
                data);
        decPane.setCipherText(Util.byteArrayToString(out, false, 20));
    }

    void actionHash() {
        byte[] data = null;
        if (sigPane.getHex()) {
            data = Util.stringToByteArray(sigPane.getDTBSText());
        } else {
            data = sigPane.getDTBSText().getBytes();
        }

        if (data == null || data.length == 0)
            return;

        byte[] out = null;
        String algName = sigPane.getSHA1() ? "SHA1" : "SHA256";
        boolean wrapped = sigPane.getPKCS();
        out = CryptoUtils.getHash(algName, data, wrapped);
        sigPane.setHashText(Util.byteArrayToString(out, false));
    }

    void actionSignatureVerify() {
        int certindex = 0;
        if (sigPane.getAuth()) {
            certindex = 3;
        } else {
            certindex = 4;
        }
        byte[] dtbs = null;
        if (sigPane.getHex()) {
            dtbs = Util.stringToByteArray(sigPane.getDTBSText());
        } else {
            dtbs = sigPane.getDTBSText().getBytes();
        }

        if (dtbs == null || dtbs.length == 0) {
            JOptionPane.showMessageDialog(this,
                    "No input data (DTBS) to verify.");
            return;
        }
        byte[] sig = Util.stringToByteArray(sigPane.getSignatureText());
        if (sig == null || sig.length == 0) {
            JOptionPane.showMessageDialog(this, "No Signature to verify.");
            return;
        }
        if (certificates[certindex] == null) {
            JOptionPane.showMessageDialog(this,
                    "No required certificate loaded.");
            return;
        }
        boolean result = false;
        PublicKey k = certificates[certindex].getPublicKey();
        if (sigPane.getAuth()) {
            result = CryptoUtils.pkcs1DecryptCompare(k, sig, dtbs);
        } else {
            if (sigPane.getPKCS()) {
                result = CryptoUtils.pkcs1Verify(k, dtbs, sig, !sigPane
                        .getSHA1());

            } else {
                result = CryptoUtils.pssVerify(k, dtbs, sig);

            }
        }
        sigPane.setVerified(result);

    }

    void actionSign() throws CardServiceException {
        byte[] data = null;
        if (sigPane.getHex())
            data = Util.stringToByteArray(sigPane.getDTBSText());
        else
            data = sigPane.getDTBSText().getBytes();

        if (!sigPane.getAuth()) {
            String algName = sigPane.getSHA1() ? "SHA1" : "SHA256";
            boolean wrapped = sigPane.getPKCS();
            data = CryptoUtils.getHash(algName, data, wrapped);
        }
        if (data == null || data.length == 0)
            return;
        PINEnterDialog pe = new PINEnterDialog(this, "Enter PIN", 4, 20);
        char[] c = pe.getPIN();
        if (c == null)
            return;

        byte[] p = new byte[c.length];
        for (int i = 0; i < p.length; i++) {
            p[i] = (byte) c[i];
        }
        byte[] keyId = pi.getPrivateKeyPane().getKeyId(
                sigPane.getAuth() ? 0 : 1);
        if (keyId == null)
            return;

        byte algId = 0;
        if (sigPane.getAuth()) {
            algId = (byte) 0x01;
        } else {
            if (sigPane.getPKCS()) {
                if (sigPane.getSHA1()) {
                    algId = (byte) 0x02;
                } else {
                    algId = (byte) 0x03;
                }

            } else {
                // PSS
                algId = (byte) 0x04;
            }
        }
        service.manageSecurityEnvironment(
                sigPane.getAuth() ? PKIService.MSE_AUTH : PKIService.MSE_SIGN,
                keyId, algId);
        service.verifyPIN(p);
        byte[] result = null;
        if (sigPane.getAuth()) {
            result = service.internalAuthenticate(data, 128);
        } else {
            result = service.computeDigitalSignature(data, 128);
        }
        sigPane.setSignatureText(Util.byteArrayToString(result, false, 64));
    }

    void actionUseDTBS() {
        String t = chalPane.getChallenge();
        if (t == null || t.equals(""))
            return;
        sigPane.setHex(true);
        sigPane.setDTBSText(t);

    }

    void actionGetChallenge() throws CardServiceException {
        int length = chalPane.getLength();
        if (length == -1)
            return;

        byte[] r = service.getChallenge((short) length);
        chalPane.setChallenge(Util.byteArrayToString(r, false, 64));
    }

    void actionSetHist() {
        try {
            byte[] hist = pi.getHistoricalBytes();
            if (hist != null) {
                service.setHistoricalBytes(hist);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void actionPerformed(ActionEvent e) {
        String command = e.getActionCommand();
        try {
            if ("sethist".equals(command)) {
                actionSetHist();
            } else if ("restorepuc".equals(command)) {
                pi.setPUC(PKIPersoService.DEFAULT_PUC);
            } else if ("init".equals(command)) {
                actionInitialize();
            } else if (command.startsWith("viewkey")) {
                int num = getCommandNum("viewkey", command);
                actionViewKey(num);
            } else if (command.startsWith("viewcert")) {
                int num = getCommandNum("viewcert", command);
                actionViewCert(num);
            } else if (command.startsWith("restorekey")) {
                int num = getCommandNum("restorekey", command);
                actionRestoreKey(num);
            } else if (command.startsWith("restorecert")) {
                int num = getCommandNum("restorecert", command);
                actionRestoreCert(num);
            } else if ("finishinit".equals(command)) {
                service.setState((byte) 2);
            } else if (command.startsWith("cardgetcert")) {
                int num = getCommandNum("cardgetcert", command);
                actionCardGetCert(num);
            } else if (command.startsWith("loadcert")) {
                int num = getCommandNum("loadcert", command);
                actionLoadCert(num);
            } else if (command.startsWith("viewcardcert")) {
                int num = getCommandNum("viewcardcert", command);
                new ViewWindow(this, "Certificate view", "" + certificates[num]);
            } else if (command.startsWith("clearcert")) {
                int num = getCommandNum("clearcert", command);
                actionClearCert(num);
            } else if (command.startsWith("verifycert")) {
                int num = getCommandNum("verifycert", command);
                actionVerifyCert(num);
            } else if ("setpin".equals(command)) {
                actionSetPIN();
            } else if ("verifypin".equals(command)) {
                actionVerifyPIN();
            } else if ("encfile".equals(command)) {
                actionEncFile();
            } else if ("decrypt".equals(command)) {
                actionDecrypt();
            } else if ("enctext".equals(command)) {
                actionEncText();
            } else if ("hash".equals(command)) {
                actionHash();
            } else if ("sigverify".equals(command)) {
                actionSignatureVerify();
            } else if ("sign".equals(command)) {
                actionSign();
            } else if ("usedtbs".equals(command)) {
                actionUseDTBS();
            } else if ("getchallenge".equals(command)) {
                actionGetChallenge();
            }
        } catch (CardServiceException cse) {
            apduLog.log("Failure during processing: " + cse.toString());
        }
    }

    static int getCommandNum(String prefix, String command) {
        int num = 0;
        try {
            num = Integer.parseInt(command.substring(prefix.length()));
        } catch (NumberFormatException nfe) {
        }
        return num;
    }

    public static String openFile(Component parent, String title) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(title);
        fc.showOpenDialog(parent);
        File f = fc.getSelectedFile();
        if (f == null || !f.exists() || !f.isFile())
            return null;
        String inData = "";
        try {
            BufferedInputStream fi = new BufferedInputStream(
                    new FileInputStream(f));
            int c = 0;
            c = fi.read();
            while (c != -1) {
                inData = inData + new String(new char[] { (char) c });
                c = fi.read();
            }
        } catch (IOException ioe) {
            JOptionPane.showMessageDialog(parent, "Could not load file \""
                    + f.getName() + "\"");
            return null;
        }
        return inData;
    }

    public static File getFile(Component parent, String title) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(title);
        fc.showOpenDialog(parent);
        File f = fc.getSelectedFile();
        if (f == null || !f.exists() || !f.isFile())
            return null;
        return f;
    }

    public static void saveFile(Component parent, String title, String text) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(title);
        fc.showSaveDialog(parent);
        File f = fc.getSelectedFile();
        int r = 0;
        if (f == null)
            return;
        if (f.exists()) {
            r = JOptionPane.showConfirmDialog(parent, "File \"" + f.getName()
                    + "\" exists. Overwrite?");
        }
        if (r != 0)
            return;
        try {
            if (!f.exists())
                f.createNewFile();
            PrintStream o = new PrintStream(f);
            o.print(text);
            o.flush();
            o.close();
        } catch (IOException ioe) {
            JOptionPane.showMessageDialog(parent, "Could not save file \""
                    + f.getName() + "\"");

        }

    }

    public static void main(String[] args) throws IOException {
        if(args.length > 0) {
            BatchWriter.main(args);
        }else{
            PKIAppletManager manager = PKIAppletManager.getInstance();
            manager.addPKIAppletListener(new MainGUI());
            CardManager cm = CardManager.getInstance();
            for (CardTerminal t : cm.getTerminals()) {
                cm.startPolling(t);
            }            
        }
    }

    public void exchangedAPDU(APDUEvent apduEvent) {
        apduLog.logCommand(apduEvent.getCommandAPDU().getBytes());
        ResponseAPDU rapdu = apduEvent.getResponseAPDU();
        apduLog.logResponse(rapdu.getBytes(), rapdu.getSW() == 0x9000);
    }

    public void pkiAppletInserted(PKIAppletEvent pe) {
        apduLog.log("Inserted PKI card.");
        try {
            service = new PKIPersoService(pe.getService());
            service.open();
            if (service != null) {
                service.addAPDUListener(this);
                setEnabled(true);
            }
        } catch (Exception e) {
            apduLog.log("PKI open failed: " + e.toString());
        }
    }

    public void pkiAppletRemoved(PKIAppletEvent pe) {
        apduLog.log("Removed PKI card.");
        service = null;
        setEnabled(false);
    }

    public void cardInserted(CardEvent ce) {
        apduLog.log("Inserted card.");
    }

    public void cardRemoved(CardEvent ce) {
        apduLog.log("Removed card.");
    }

}
