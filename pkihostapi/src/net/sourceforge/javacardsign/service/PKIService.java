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

package net.sourceforge.javacardsign.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import net.sourceforge.scuba.smartcards.APDUListener;
import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;

/**
 * High level service for the PKI applet card.
 * 
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 * 
 */
public class PKIService extends CardService {

    public static final String OID_RSA = "1.2.840.113549.1.1.1";

    public static final String OID_RSA_SHA1 = "1.2.840.113549.1.1.5";

    public static final String OID_RSA_PSS = "1.2.840.113549.1.1.10";

    public static final String OID_RSA_SHA256 = "1.2.840.113549.1.1.11";

    public static final String OID_SHA1 = "1.3.14.3.2.26";

    public static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1";

    public static final byte[] PKIAID = Util
            .stringToByteArray("A0 00 00 00 63 50 4B 43 53 2D 31 35");

    /** INStructions */
    static final byte INS_SELECT = (byte) 0xA4;

    static final byte INS_READBINARY = (byte) 0xB0;

    static final byte INS_VERIFY = (byte) 0x20;

    static final byte INS_CHANGEREFERENCEDATA = (byte) 0x24;

    static final byte INS_PUTDATA = (byte) 0xDA;

    static final byte INS_GETCHALLENGE = (byte) 0x84;

    static final byte INS_MSE = (byte) 0x22;

    static final byte INS_PSO = (byte) 0x2A;

    static final byte INS_INTERNALAUTHENTICATE = (byte) 0x88;

    public static final int MSE_AUTH = 1;

    public static final int MSE_SIGN = 2;

    public static final int MSE_DEC = 3;

    protected CardService service;

    public PKIService() {
    }

    public PKIService(CardService service) {
        this.service = service;
    }

    public void addAPDUListener(APDUListener l) {
        service.addAPDUListener(l);
    }

    public void removeAPDUListener(APDUListener l) {
        service.removeAPDUListener(l);
    }

    protected void checkSW(ResponseAPDU r, String message)
            throws CardServiceException {
        if (r.getSW() != 0x9000) {
            throw new CardServiceException(message
                    + Util.byteArrayToString(new byte[] { (byte) r.getSW1(),
                            (byte) r.getSW2() }, false));
        }
    }

    /**
     * Select the file of the given id.
     * 
     * @param id
     *            the id of the file to be selected on the card
     * @throws CardServiceException
     *             on errors
     */
    public void selectFile(short id) throws CardServiceException {
        byte[] data = { (byte) (id >> 8), (byte) (id & 0xFF)};
        CommandAPDU c = new CommandAPDU(0, INS_SELECT, 0, 0, data, 256);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "selectFile failed: ");
    }

    /**
     * Read the currently selected file contents.
     * 
     * @param offset
     *            the offset in the file
     * @param len
     *            the number of requested bytes
     * @return the data read from the card
     * @throws CardServiceException
     *             on errors
     */
    public byte[] readFile(short offset, byte len) throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, INS_READBINARY, (byte) (offset >> 8), (byte) (offset & 0xFF), len);
        ResponseAPDU r = service.transmit(c);
        byte[] result = r.getBytes();
        
        if (result[result.length - 2] == 0x62
                && result[result.length - 1] == (byte) 0x82) {
            result[result.length - 2] = (byte) 0x90;
            result[result.length - 1] = (byte) 0x00;
            r = new ResponseAPDU(result);
        }
        checkSW(r, "readFile failed: ");
        return r.getData();
    }

    /**
     * Read the whole file in (select and read file until EOF)
     * 
     * @param id
     *            the id of the file to be read
     * @return the contents of the file
     * @throws CardServiceException
     *             on errors
     */
    public byte[] readFile(short id) throws CardServiceException {
        return readFile(id, null);
    }

    /**
     * Read the whole file in (select and read file until EOF)
     * 
     * @param id
     *            the id of the file to be read
     * @param PIN
     *            if required by the card to read the given file, can be null
     * @return the contents of the file
     * @throws CardServiceException
     *             on errors
     */
    public byte[] readFile(short id, byte[] pin) throws CardServiceException {
        try {
            selectFile(id);
            if (pin != null) {
                verifyPIN(pin);
            }
            short offset = 0;
            int blockSize = 128;
            ByteArrayOutputStream collect = new ByteArrayOutputStream();
            while (true) {
                byte[] temp = readFile(offset, (byte) blockSize);
                collect.write(temp);
                offset += temp.length;
                if (temp.length < blockSize) {
                    break;
                }
            }
            return collect.toByteArray();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            throw new CardServiceException(ioe.getMessage());
        }
    }

    /**
     * Verify the user PIN with the card.
     * 
     * @param pinData
     *            the PIN data
     * @throws CardServiceException
     *             on unsuccessful PIN verification or error
     */
    public void verifyPIN(byte[] pinData) throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, INS_VERIFY, 0, 0, pinData);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "verifyPIN failed: ");
    }

    /**
     * Changes the user PIN on the card.
     * 
     * @param pucData
     *            the PUC code data for verification
     * @param pinData
     *            the new PIN data
     * @throws CardServiceException
     *             on errors (eg. wrong PUC)
     */
    public void changePIN(byte[] pucData, byte[] pinData)
            throws CardServiceException {
        ByteArrayOutputStream apduData = new ByteArrayOutputStream();
        try {
          apduData.write(pucData);
          apduData.write(pinData);
        }catch(IOException ioe) {
            // Should not happen, just in case
            ioe.printStackTrace();
        }
        CommandAPDU c = new CommandAPDU(0, INS_CHANGEREFERENCEDATA, 0, 0, apduData.toByteArray());
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "changePIN failed: ");
    }

    /**
     * Get a random challange from the card.
     * 
     * @param length
     *            the challenge length
     * @return the challenge
     * @throws CardServiceException
     *             on error
     */
    public byte[] getChallenge(short length) throws CardServiceException {
        if (length <= 0 || length > 256) {
            throw new IllegalArgumentException(
                    "Lenght must be between 1 and 256 inclusive.");
        }
        CommandAPDU c = new CommandAPDU(0, INS_GETCHALLENGE, 0, 0, length);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "getChallenge failed: ");
        return r.getData();
    }

    /**
     * Manage security environment - prepare the card for the upcoming cipher
     * operation.
     * 
     * @param mode
     *            MSE_AUTH, MSE_SIGN, or MSE_DEC
     * @param keyId
     *            the id of the key on the card. A valid keyId can be read from
     *            the card's private key directory file (EF.PrKD)
     * @param algSpec
     *            the byte matching the algorithm specification, a valid should
     *            be retrievable from the card's file system (the EF.CIAInfo
     *            file).
     * 
     * @throws CardServiceException
     *             on errors
     */
    public void manageSecurityEnvironment(int mode, byte[] keyId, byte algSpec)
            throws CardServiceException {
        try {
            byte p2 = 0;
            switch (mode) {
            case MSE_AUTH:
                p2 = (byte) 0xa4;
                break;
            case MSE_SIGN:
                p2 = (byte) 0xb6;
                break;
            case MSE_DEC:
                p2 = (byte) 0xb8;
                break;
            default:
                throw new CardServiceException("Wrong mode.");
            }
            ByteArrayOutputStream apduData = new ByteArrayOutputStream();
            apduData.write((byte) 0x84);
            apduData.write((byte) keyId.length);
            apduData.write(keyId);
            apduData.write((byte) 0x80);
            apduData.write(0x01);
            apduData.write(algSpec);
            CommandAPDU c = new CommandAPDU(0, INS_MSE, 0x41, p2, apduData
                    .toByteArray());
            ResponseAPDU r = service.transmit(c);
            checkSW(r, "manageSecureEnvironment failed: ");
        } catch (IOException ioe) {
            ioe.printStackTrace();
            throw new CardServiceException(ioe.getMessage());
        }
    }

    /**
     * Send Perform Security Operation Decipher command(s) to the card. Should
     * be only possible with the previous MSE command with the MSE_DEC mode. PIN
     * authentication is usually required immediately prior to PSO commands.
     * 
     * @param cipherBlock
     *            the cipher text to be decrypted
     * @param expLen
     *            expeceted length of the response
     * @return the decrypted plain text
     * @throws CardServiceException
     *             on errors
     */
    public byte[] decipher(byte[] cipherBlock, byte expLen)
            throws CardServiceException {
        ByteArrayOutputStream apduData = new ByteArrayOutputStream();
        CommandAPDU apdu1 = null;
        CommandAPDU apdu2 = null;
        int maxBlock = 126; // 254
        int blockSize = 60; // 128
        if (cipherBlock.length > maxBlock) {
            apduData.write(cipherBlock, 0, blockSize);
            apdu1 = new CommandAPDU((byte)0x10, INS_PSO, (byte) 0x80, (byte) 0x86, apduData.toByteArray(), expLen);

            apduData.reset();
            apduData.write(cipherBlock, blockSize, cipherBlock.length - blockSize);
            apdu2 = new CommandAPDU(0, INS_PSO, (byte) 0x80, (byte) 0x86, apduData.toByteArray(), expLen);
        } else {
            apdu2 = new CommandAPDU(0, INS_PSO, (byte) 0x80, (byte) 0x86, cipherBlock, expLen);
        }
        byte[] res1 = new byte[0];
        if (apdu1 != null) {
            ResponseAPDU r = service.transmit(apdu1);
            checkSW(r, "decipher1 failed: ");
            res1 = r.getData();
        }
        ResponseAPDU r = service.transmit(apdu2);
        checkSW(r, "decipher2 failed: ");

        apduData.reset();
        try{
          apduData.write(res1);
          apduData.write(r.getData());
        }catch(IOException ioe) {
            ioe.printStackTrace();
        }
        return apduData.toByteArray();
    }

    /**
     * Send Perform Security Operation Sign command to the card. Should be only
     * possible with the previous MSE command with the MSE_SIGN mode. PIN
     * authentication is usually required immediately prior to PSO commands.
     * 
     * @param text
     *            (the hash of) the plain text to be signed
     * @param expLen
     *            expeceted length of the response
     * @return the signature of the provided text
     * @throws CardServiceException
     *             on errors
     */
    public byte[] computeDigitalSignature(byte[] text, byte expLen)
            throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, INS_PSO, (byte) 0x9E, (byte) 0x9A, text, expLen);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "computeDigitalSignature failed: ");
        return r.getData();
    }

    /**
     * Send Internal Authenticate command to the card. Should be only possible
     * with the previous MSE command with the MSE_AUTH mode. PIN authentication
     * is usually required immediately prior to Internal Authenticate commands.
     * 
     * @param text
     *            the plain text to be signed
     * @param expLen
     *            expeceted length of the response
     * @return the signature of the plain text
     * @throws CardServiceException
     *             on errors
     */
    public byte[] internalAuthenticate(byte[] text, byte expLen)
            throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, INS_INTERNALAUTHENTICATE, 0, 0, text, expLen);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "computeDigitalSignature failed: ");
        return r.getData();
    }

    /**
     * Selects the PKI applet on the card.
     * 
     * @throws CardServiceException
     *             on error
     */
    public void sendSelectApplet() throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, 0xA4, (byte) 0x04, (byte) 0x00,
                PKIAID);
        ResponseAPDU r = transmit(c);
        if (r.getSW() != 0x00009000) {
            throw new CardServiceException("Could not select the PKI applet.");
        }

    }

    /**
     * Closes this service.
     */
    public void close() {
        if (service != null) {
            service.close();
        }
    }

    /**
     * Checks if the service is currently open.
     */
    public boolean isOpen() {
        return service.isOpen();
    }

    /**
     * Opens the service.
     */
    public void open() throws CardServiceException {
        if (!service.isOpen()) {
            service.open();
        }
        sendSelectApplet();
    }

    /**
     * Trasmits the APDU to the card.
     */
    public ResponseAPDU transmit(CommandAPDU apdu) throws CardServiceException {
        return service.transmit(apdu);
    }

}
