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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import net.sourceforge.javacardsign.service.*;

import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardEvent;
import net.sourceforge.scuba.smartcards.CardManager;

public class BatchWriter implements APDUListener, PKIAppletListener {

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
        System.out
                .println("  zipfile contains the required data files for the PKI card");
        System.out.println();
    }

    public void takeApart(File zipFile) throws IOException {
        ZipFile zipIn = new ZipFile(zipFile);
        Enumeration<? extends ZipEntry> entries = zipIn.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            byte[] data = readEntry(zipIn, entry);
            String name = entry.getName();
            doEntry(name, data);
        }
    }

    private byte[] readEntry(ZipFile zipIn, ZipEntry entry) throws IOException {
        int size = (int) (entry.getSize() & 0x00000000FFFFFFFFL);
        byte[] data = new byte[size];
        DataInputStream dataIn = new DataInputStream(zipIn
                .getInputStream(entry));
        dataIn.readFully(data);
        return data;
    }

    private void doEntry(String name, byte[] data) throws IOException {
        try {
            if (name.equals("pin.txt")) {
                if (data.length < 4 || data.length > 20) {
                    throw new IllegalArgumentException("Wrong PIN length");
                }
                pin = new String(data);
            } else if (name.equals("puc.txt")) {
                if (data.length != 16) {
                    throw new IllegalArgumentException("Wrong PUC length");
                }
                puc = new String(data);

            } else if (name.equals("authkeyid.bin")) {
                if (data.length <= 0 || data.length > 16) {
                    throw new IllegalArgumentException(
                            "Wrong Auth key ID length");
                }
                authKeyId = data;
            } else if (name.equals("deckeyid.bin")) {
                if (data.length <= 0 || data.length > 16) {
                    throw new IllegalArgumentException(
                            "Wrong Dec key ID length");
                }
                decKeyId = data;
            } else if (name.equals("signkeyid.bin")) {
                if (data.length <= 0 || data.length > 16) {
                    throw new IllegalArgumentException(
                            "Wrong Sign key ID length");
                }
                signKeyId = data;
            } else if (name.equals("historical.bin")) {
                historical = data;
            } else if (name.equals("authkey.der")) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                authKey = (RSAPrivateCrtKey) kf
                        .generatePrivate(new PKCS8EncodedKeySpec(data));
            } else if (name.equals("deckey.der")) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                decKey = (RSAPrivateCrtKey) kf
                        .generatePrivate(new PKCS8EncodedKeySpec(data));
            } else if (name.equals("signkey.der")) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                signKey = (RSAPrivateCrtKey) kf
                        .generatePrivate(new PKCS8EncodedKeySpec(data));
            } else if (name.equals("authcert.der")) {
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                authCert = (X509Certificate) cf
                        .generateCertificate(new ByteArrayInputStream(data));

            } else if (name.equals("signcert.der")) {
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                signCert = (X509Certificate) cf
                        .generateCertificate(new ByteArrayInputStream(data));

            } else if (name.equals("deccert.der")) {
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                decCert = (X509Certificate) cf
                        .generateCertificate(new ByteArrayInputStream(data));

            } else if (name.equals("cacert.der")) {
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                caCert = (X509Certificate) cf
                        .generateCertificate(new ByteArrayInputStream(data));

            } else {
                System.out.println("Don't know what to do with " + name);
            }

        } catch (Exception ex) {
            throw new IOException("Reading of " + name + " failed: "
                    + ex.getMessage());
        }
    }

    public void uploadPKI() {
        try {
            Object[] data = new Object[] { pin, puc, authKey, signKey, decKey,
                    caCert, authCert, signCert, decCert, authKeyId, signKeyId,
                    decKeyId };
            for (Object o : data) {
                if (o == null) {
                    throw new IOException("Missing required data.");
                }
            }
            if (historical != null) {
                service.setHistoricalBytes(historical);
            }
            service.initializeApplet(caCert, authCert, signCert, decCert,
                    authKey, signKey, decKey, authKeyId, signKeyId, decKeyId,
                    puc);
            service.changePIN(puc.getBytes(), pin.getBytes());

            System.out.println("Data uploaded.");
        } catch (Exception ex) {
            System.out.println("Uploading failed.");
            ex.printStackTrace();
            System.exit(-1);

        }
    }

    public BatchWriter(String[] args) throws IOException {
        if (args.length != 1) {
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
        System.out.println("C: "
                + Util.byteArrayToString(capdu.getBytes(), false));
        System.out.println("R: "
                + Util.byteArrayToString(rapdu.getBytes(), false));
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
