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

import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardEvent;
import net.sourceforge.scuba.smartcards.CardManager;
import net.sourceforge.scuba.smartcards.CardServiceException;

public class BatchWriter implements APDUListener,
        PKIAppletListener {

    private PKIPersoService service = null;

    private byte[] historical = null;
    private String puc = null;
    private String pin = null;
    
    private RSAPrivateCrtKey authKey = null;
    private RSAPrivateCrtKey signKey = null;
    private RSAPrivateCrtKey decKey = null;
    
    private X509Certificate caCert = null;
    private X509Certificate authCert = null;
    private X509Certificate signCert = null;
    private X509Certificate decCert = null;

    private byte[] authKeyId = null;
    private byte[] signKeyId = null;
    private byte[] decKeyId = null;

    
    public static void usage() {
        System.out.println("Usage:");
        System.out.println("  java -jar pkihost.jar batch <zipfile>");
        System.out.println();
        System.out.println("  zipfile contains the required data files for the PKI card");
        System.out.println();
    }

    public void takeApart(File zipFile) throws IOException {
        
    }
    
    public void uploadPKI() {
        try {
        Object[] data = new Object[] {
          pin, puc, authKey, signKey, decKey, caCert, authCert, signCert, decCert,
          authKeyId, signKeyId, decKeyId };
        for(Object o : data) {
            if(o == null) {
                throw new IOException("Missing required data.");
            }
        }
        if(historical != null) {
            service.setHistoricalBytes(historical);
        }
        service.initializeApplet(caCert, authCert, signCert, decCert,
                authKey, signKey, decKey, authKeyId, signKeyId, decKeyId, puc);
        service.changePIN(puc.getBytes(), pin.getBytes());
        
        System.out.println("Data uploaded.");
        }catch(Exception ex) {
            System.out.println("Uploading failed.");
            ex.printStackTrace();
            System.exit(-1);
            
        }
    }
    
    
    public BatchWriter(String[] args) throws IOException {
        if(args.length != 1) {
            usage();
            System.exit(-1);
        }
        File zipFile = new File(args[0]);
        takeApart(zipFile);
    }


    public static void main(String[] args) throws IOException {
      PKIAppletManager manager = PKIAppletManager.getInstance();
      manager.addPKIAppletListener(new BatchWriter(args));
      CardManager cm = CardManager.getInstance();
      for (CardTerminal t : cm.getTerminals()) {
        cm.startPolling(t);
      }
    }

    public void exchangedAPDU(CommandAPDU capdu, ResponseAPDU rapdu) {
        System.out.println("C: "+Util.byteArrayToString(capdu.getBytes(), false));
        System.out.println("R: "+Util.byteArrayToString(rapdu.getBytes(), false));
    }

    public void pkiAppletInserted(PKIAppletEvent pe) {
        System.out.println("Inserted PKI card.");
        try {
            service = new PKIPersoService(pe.getService());
            service.open();
            if (service != null) {
                service.addAPDUListener(this);
                uploadPKI();
                System.exit(0);
            }
        } catch (Exception e) {
            System.out.println("PKI open failed: " + e.toString());
        }
    }

    public void pkiAppletRemoved(PKIAppletEvent pe) {
        System.out.println("Removed PKI card.");
        System.exit(-1);
    }

    public void cardInserted(CardEvent ce) {
        System.out.println("Inserted card.");
    }

    public void cardRemoved(CardEvent ce) {
        System.out.println("Removed card.");
    }

}
