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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import net.sourceforge.javacardsign.iso7816_15.AlgorithmInfo;
import net.sourceforge.javacardsign.iso7816_15.AuthenticationObjectDirectoryEntry;
import net.sourceforge.javacardsign.iso7816_15.CertificateDirectoryEntry;
import net.sourceforge.javacardsign.iso7816_15.CommonAuthenticationObjectAttributes;
import net.sourceforge.javacardsign.iso7816_15.CommonCertificateAttributes;
import net.sourceforge.javacardsign.iso7816_15.CommonKeyAttributes;
import net.sourceforge.javacardsign.iso7816_15.CommonObjectAttributes;
import net.sourceforge.javacardsign.iso7816_15.ElementaryFileAuthenticationObjectDirectory;
import net.sourceforge.javacardsign.iso7816_15.ElementaryFileCIAInfo;
import net.sourceforge.javacardsign.iso7816_15.ElementaryFileCertificateDirectory;
import net.sourceforge.javacardsign.iso7816_15.ElementaryFileDIR;
import net.sourceforge.javacardsign.iso7816_15.ElementaryFileObjectDirectory;
import net.sourceforge.javacardsign.iso7816_15.ElementaryFilePrivateKeyDirectory;
import net.sourceforge.javacardsign.iso7816_15.ObjectDirectoryEntry;
import net.sourceforge.javacardsign.iso7816_15.PasswordAttributes;
import net.sourceforge.javacardsign.iso7816_15.PrivateKeyAttributes;
import net.sourceforge.javacardsign.iso7816_15.RSAPrivateKeyAttributes;
import net.sourceforge.javacardsign.iso7816_15.RSAPrivateKeyDirectoryEntry;
import net.sourceforge.javacardsign.iso7816_15.X509CertificateAttributes;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;

/**
 * Personalisation service for our PKI applet.
 * 
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 *
 */
public class PKIPersoService extends PKIService {

    /** Default PUC */ 
    public static final String DEFAULT_PUC = "0123456789012345";

    /** Additional APDUs needed for personalisation */
    static final byte INS_WRITEBINARY = (byte) 0xD0;
    static final byte INS_CREATEFILE = (byte) 0xE0;

    /** File IDs for ceriticates */
    public static int CA_CERT_FID = 0x4101;
    public static int USER_AUTH_CERT_FID = 0x4102;
    public static int USER_SIGN_CERT_FID = 0x4103;
    public static int USER_DEC_CERT_FID = 0x4104;

    /** The data structure hierarchical file system for the file system
     *  in our applet. The data is as follows, concatenated in sequence:
     *  
     *  byte 0: -1/0   -1 for DF, 0 for EF
     *  byte 1, 2: fid msb, fid lsb
     *  byte 3: index to the parent in this array, -1 of root node
     *  byte 4: for EF the SFI of this file
     *          for DF number of children nodes, the list of indexes to the children follow
     *  
     */
    public static final byte[] fileStructure = {
    		-1, 0x3F, 0x00, -1, 2, 7, 12, // MF
            0, 0x2F, 0x00, 0, 0x1E, // EF.DIR
            -1, 0x50, 0x15, 0, 9, 26, 31, 36, 41, 46, 51, 56, 61, 66, // DF.CIA
            0, 0x50, 0x32, 12, 0x12, // EF.CIAInfo
            0, 0x50, 0x31, 12, 0x11, // EF.OD
            0, 0x42, 0x00, 12, 0x00, // EF.AOD
            0, 0x40, 0x00, 12, 0x00, // EF.PrKD
            0, 0x41, 0x00, 12, 0x00, // EF.CD
            0, 0x41, 0x01, 12, 0x00, // EF.CACert
            0, 0x41, 0x02, 12, 0x00, // EF.UserCert1
            0, 0x41, 0x03, 12, 0x00, // EF.UserCert2
            0, 0x41, 0x04, 12, 0x00, // EF.UserCert3
    };

    public PKIPersoService(CardService service) {
        this.service = service instanceof PKIService ? ((PKIService) service).service
                : service;
    }

    /**
     * Set the historical bytes on the card. The PKI applet needs to be default selectable for that.
     * @param histBytes the array with historical bytes to be set
     * @throws CardServiceException on error
     */
    public void setHistoricalBytes(byte[] histBytes)
            throws CardServiceException {
        byte[] apdu = new byte[6 + histBytes.length];
        apdu[1] = INS_PUTDATA;
        apdu[2] = 0x67;
        apdu[4] = (byte) (histBytes.length & 0xff);
        System.arraycopy(histBytes, 0, apdu, 5, histBytes.length);
        CommandAPDU c = new CommandAPDU(apdu);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "setHistoricalBytes failed: ");
    }

    /**
     * Set the default PUC on the card.
     * @throws CardServiceException on error
     */
    public void setPUC() throws CardServiceException {
        setPUC(DEFAULT_PUC);
    }

    /**
     * Set the given PUC on the card.
     * @param puc the PUC string 
     * @throws CardServiceException on errors
     */
    public void setPUC(String puc) throws CardServiceException {
        byte[] apdu = new byte[6 + puc.length()];
        apdu[1] = INS_CHANGEREFERENCEDATA;
        apdu[2] = 0x01;
        apdu[4] = (byte) (puc.length() & 0xff);
        for (int i = 0; i < puc.length(); i++) {
            apdu[5 + i] = (byte) puc.charAt(i);
        }
        CommandAPDU c = new CommandAPDU(apdu);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "setPUC failed: ");
    }

    /**
     * Set the personalisation state of the applet.
     * @param state the state, valid values are:
     *          1 initial
     *          2 prepersonalised (keys, certs loaded, no PIN set)
     *          3 personalised
     * @throws CardServiceException on error
     */
    public void setState(byte state) throws CardServiceException {
        byte[] apdu = new byte[5];
        apdu[1] = INS_PUTDATA;
        apdu[2] = 0x68;
        apdu[3] = state;
        apdu[4] = 0;
        CommandAPDU c = new CommandAPDU(apdu);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "setState failed: ");
    }

    /**
     * Create a file in the applet. Note that the file system structure has to be established first.
     * @param fid the ID of the file to create
     * @param length the required length of the file
     * @param pin whether the reading of the file should be PIN protected
     * @throws CardServiceException on error
     */
    public void createFile(int fid, int length, boolean pin)
    throws CardServiceException {
byte[] apdu = new byte[10];
apdu[1] = INS_CREATEFILE;
apdu[4] = 5;
apdu[5] = (byte) (fid >> 8);
apdu[6] = (byte) (fid & 0xFF);
apdu[7] = (byte) (length >> 8);
apdu[8] = (byte) (length & 0xFF);
apdu[9] = (byte) (pin ? 0x01 : 0x00);
CommandAPDU c = new CommandAPDU(apdu);
ResponseAPDU r = service.transmit(c);
checkSW(r, "createFile failed: ");
}

    /**
     * Write a piece of data to the file in the applet.
     * @param data the data to be written array
     * @param dOffset offset to that array
     * @param dLen length of the data to be written
     * @param fOffset offset in the file in the applet
     * @throws CardServiceException on error
     */
    public void writeFile(byte[] data, short dOffset, byte dLen, short fOffset)
            throws CardServiceException {
        byte[] apdu = new byte[6 + (dLen & 0xFF)];
        apdu[1] = INS_WRITEBINARY;
        apdu[2] = (byte) (fOffset >> 8);
        apdu[3] = (byte) (fOffset & 0xFF);
        apdu[4] = dLen;
        System.arraycopy(data, dOffset, apdu, 5, (dLen & 0xff));
        CommandAPDU c = new CommandAPDU(apdu);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "writeFile failed: ");
    }


    public void initializeApplet(X509Certificate caCert,
            X509Certificate userAuthCertificate,
            X509Certificate userSignCertificate,
            X509Certificate userDecCertificate, RSAPrivateCrtKey authKey,
            RSAPrivateCrtKey signKey, RSAPrivateCrtKey decKey,
            byte[] authKeyId, byte[] signKeyId, byte[] decKeyId, String pucData)
            throws CardServiceException {
        try {
            setState((byte) 1);
            createFileStructure(fileStructure);
            byte[] idAuth = { 0x45 };
            byte[] idSign = { 0x46 };
            byte[] idDec = { 0x47 };

            setKeys(authKeyId, signKeyId, decKeyId, authKey, signKey, decKey);
            setCertificate(CA_CERT_FID, caCert, false);
            setCertificate(USER_AUTH_CERT_FID, userAuthCertificate, false);
            setCertificate(USER_SIGN_CERT_FID, userSignCertificate, false);
            setCertificate(USER_DEC_CERT_FID, userDecCertificate, false);
            CommonObjectAttributes authCoa = new CommonObjectAttributes(
                    "UserAuthKey", (byte) 0x01,
                    new byte[] { CommonObjectAttributes.FLAG_PRIVATE });
            CommonObjectAttributes signCoa = new CommonObjectAttributes(
                    "UserSignKey", (byte) 0x02,
                    new byte[] { CommonObjectAttributes.FLAG_PRIVATE });
            CommonObjectAttributes decCoa = new CommonObjectAttributes(
                    "UserDecKey", (byte) 0x03,
                    new byte[] { CommonObjectAttributes.FLAG_PRIVATE });

            CommonKeyAttributes authCka = new CommonKeyAttributes(idAuth,
                    new byte[] { CommonKeyAttributes.USAGE_ENC,
                            CommonKeyAttributes.USEAGE_NON_REP });
            CommonKeyAttributes signCka = new CommonKeyAttributes(idSign,
                    new byte[] { CommonKeyAttributes.USEAGE_SIGN });
            CommonKeyAttributes decCka = new CommonKeyAttributes(idDec,
                    new byte[] { CommonKeyAttributes.USEAGE_DEC });
            PrivateKeyAttributes authPka = new PrivateKeyAttributes(authKeyId);
            PrivateKeyAttributes signPka = new PrivateKeyAttributes(signKeyId);
            PrivateKeyAttributes decPka = new PrivateKeyAttributes(decKeyId);
            RSAPrivateKeyAttributes authRpka = new RSAPrivateKeyAttributes(0,
                    gb(authKey.getModulus()).length * 8);
            RSAPrivateKeyAttributes signRpka = new RSAPrivateKeyAttributes(0,
                    gb(signKey.getModulus()).length * 8);
            RSAPrivateKeyAttributes decRpka = new RSAPrivateKeyAttributes(0,
                    gb(decKey.getModulus()).length * 8);

            RSAPrivateKeyDirectoryEntry aKd = new RSAPrivateKeyDirectoryEntry(
                    authCoa, authCka, authPka, authRpka);
            RSAPrivateKeyDirectoryEntry sKd = new RSAPrivateKeyDirectoryEntry(
                    signCoa, signCka, signPka, signRpka);
            RSAPrivateKeyDirectoryEntry dKd = new RSAPrivateKeyDirectoryEntry(
                    decCoa, decCka, decPka, decRpka);
            ElementaryFilePrivateKeyDirectory efPrkD = new ElementaryFilePrivateKeyDirectory(
                    new RSAPrivateKeyDirectoryEntry[] { aKd, sKd, dKd });
            byte[] efPrkDContents = efPrkD.getEncoded();
            createFile(0x4000, efPrkDContents.length, false);
            selectFile((short) 0x4000);
            writeFile(efPrkDContents, (short) 0, (byte) efPrkDContents.length,
                    (short) 0);

            CommonObjectAttributes caCcoa = new CommonObjectAttributes(
                    "CACert", new byte[0]);
            CommonObjectAttributes authCcoa = new CommonObjectAttributes(
                    "AuthUserCert", new byte[0]);
            CommonObjectAttributes signCcoa = new CommonObjectAttributes(
                    "SignUserCert", new byte[0]);
            CommonObjectAttributes decCcoa = new CommonObjectAttributes(
                    "DecUserCert", new byte[0]);

            CommonCertificateAttributes cacca = new CommonCertificateAttributes(
                    new byte[] { 0x55 });
            CommonCertificateAttributes authcca = new CommonCertificateAttributes(
                    idAuth);
            CommonCertificateAttributes signcca = new CommonCertificateAttributes(
                    idSign);
            CommonCertificateAttributes deccca = new CommonCertificateAttributes(
                    idDec);

            X509CertificateAttributes caxca = new X509CertificateAttributes(
                    CA_CERT_FID);
            X509CertificateAttributes authxca = new X509CertificateAttributes(
                    USER_AUTH_CERT_FID);
            X509CertificateAttributes signxca = new X509CertificateAttributes(
                    USER_SIGN_CERT_FID);
            X509CertificateAttributes decxca = new X509CertificateAttributes(
                    USER_DEC_CERT_FID);

            CertificateDirectoryEntry cace = new CertificateDirectoryEntry(
                    caCcoa, cacca, caxca);
            CertificateDirectoryEntry authce = new CertificateDirectoryEntry(
                    authCcoa, authcca, authxca);
            CertificateDirectoryEntry signce = new CertificateDirectoryEntry(
                    signCcoa, signcca, signxca);
            CertificateDirectoryEntry decce = new CertificateDirectoryEntry(
                    decCcoa, deccca, decxca);

            ElementaryFileCertificateDirectory cd = new ElementaryFileCertificateDirectory(
                    new CertificateDirectoryEntry[] { cace, authce, signce,
                            decce });
            byte[] cdContents = cd.getEncoded();
            createFile(0x4100, cdContents.length, false);
            selectFile((short) 0x4100);
            writeFile(cdContents, (short) 0, (byte) cdContents.length,
                    (short) 0);

            CommonObjectAttributes pucA = new CommonObjectAttributes("PUC",
                    new byte[] { CommonObjectAttributes.FLAG_PRIVATE });
            CommonAuthenticationObjectAttributes pucA1 = new CommonAuthenticationObjectAttributes(
                    new byte[] { 0x01 });
            PasswordAttributes pucA2 = new PasswordAttributes(new byte[] {
                    PasswordAttributes.FLAG_CHANGE_DISABLED,
                    PasswordAttributes.FLAG_UNBLOCK_DISABLED,
                    PasswordAttributes.FLAG_INITIALIZED,
                    PasswordAttributes.FLAG_UNBLOCKING_PASSWORD },
                    PasswordAttributes.TYPE_ASCII_NUM, 16, 16);
            AuthenticationObjectDirectoryEntry puc = new AuthenticationObjectDirectoryEntry(
                    pucA, pucA1, pucA2);

            CommonObjectAttributes pinA = new CommonObjectAttributes("PIN",
                    new byte[] { CommonObjectAttributes.FLAG_PRIVATE });
            CommonAuthenticationObjectAttributes pinA1 = new CommonAuthenticationObjectAttributes(
                    new byte[] { 0x02 });
            PasswordAttributes pinA2 = new PasswordAttributes(
                    new byte[] { PasswordAttributes.FLAG_INITIALIZED, },
                    PasswordAttributes.TYPE_ASCII_NUM, 4, 16);
            AuthenticationObjectDirectoryEntry pin = new AuthenticationObjectDirectoryEntry(
                    pinA, pinA1, pinA2);
            ElementaryFileAuthenticationObjectDirectory aod = new ElementaryFileAuthenticationObjectDirectory(
                    new AuthenticationObjectDirectoryEntry[] { puc, pin });
            byte[] aodContents = aod.getEncoded();
            createFile(0x4200, aodContents.length, false);
            selectFile((short) 0x4200);
            writeFile(aodContents, (short) 0, (byte) aodContents.length,
                    (short) 0);
            ObjectDirectoryEntry eAOD = new ObjectDirectoryEntry(
                    ObjectDirectoryEntry.TAG_AUTH_OBJECTS, 0x4200);
            ObjectDirectoryEntry ePrkD = new ObjectDirectoryEntry(
                    ObjectDirectoryEntry.TAG_PRIVATE_KEYS, 0x4000);
            ObjectDirectoryEntry eCD = new ObjectDirectoryEntry(
                    ObjectDirectoryEntry.TAG_CERTIFICATES, 0x4100);
            ElementaryFileObjectDirectory od = new ElementaryFileObjectDirectory(
                    new ObjectDirectoryEntry[] { eAOD, ePrkD, eCD });
            byte[] odContents = od.getEncoded();
            createFile(0x5031, odContents.length, false);
            selectFile((short) 0x5031);
            writeFile(odContents, (short) 0, (byte) odContents.length,
                    (short) 0);
            // TODO: Radboud OID?
            ElementaryFileDIR efDIR = new ElementaryFileDIR(PKIAID,
                    "PKI Applet", new byte[] { 0x3F, 0x00, 0x50, 0x15 },
                    OID_RSA + ".50");
            byte[] efDirContents = efDIR.getEncoded();
            createFile(0x2F00, efDirContents.length, false);
            selectFile((short) 0x2F00);
            writeFile(efDirContents, (short) 0, (byte) efDirContents.length,
                    (short) 0);

            AlgorithmInfo al1 = new AlgorithmInfo(1, 1, new byte[] {
                    AlgorithmInfo.OP_ENCIPHER, AlgorithmInfo.OP_DECIPHER },
                    OID_RSA, (byte) 1);
            AlgorithmInfo al2 = new AlgorithmInfo(2, 2,
                    new byte[] { AlgorithmInfo.OP_COMPUTE_SIGNATURE },
                    OID_RSA_SHA1, (byte) 2);
            AlgorithmInfo al3 = new AlgorithmInfo(3, 3,
                    new byte[] { AlgorithmInfo.OP_COMPUTE_SIGNATURE },
                    OID_RSA_SHA256, (byte) 3);
            AlgorithmInfo al4 = new AlgorithmInfo(4, 4,
                    new byte[] { AlgorithmInfo.OP_COMPUTE_SIGNATURE },
                    OID_RSA_PSS, (byte) 4);

            ElementaryFileCIAInfo efCia = new ElementaryFileCIAInfo(
                    ElementaryFileCIAInfo.V2, "Radboud", new byte[] {
                            ElementaryFileCIAInfo.CARD_FLAG_READ_ONLY,
                            ElementaryFileCIAInfo.CARD_AUTH_REQUIRED,
                            ElementaryFileCIAInfo.CARD_PRN_GENERATION },
                    new AlgorithmInfo[] { al1, al2, al3, al4 });

            byte[] ciaContents = efCia.getDERObject().getDEREncoded();
            createFile(0x5032, ciaContents.length, false);
            selectFile((short) 0x5032);
            writeFile(ciaContents, (short) 0, (byte) ciaContents.length,
                    (short) 0);

            setPUC(pucData);
            setState((byte) 2);
        } catch (Exception e) {
            throw new CardServiceException("" + e.toString());
        }
    }

    private void createFileStructure(byte[] fs) throws CardServiceException {
        byte[] apdu = new byte[5 + fs.length];
        apdu[1] = INS_PUTDATA;
        apdu[2] = 0x69;
        apdu[4] = (byte) fs.length;
        System.arraycopy(fs, 0, apdu, 5, fs.length);
        CommandAPDU c = new CommandAPDU(apdu);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "createFileStructure failed: ");
    }

    private byte[] gb(BigInteger num) {
        byte[] bytes = num.toByteArray();
        if (bytes.length == 3 || bytes.length % 8 == 0) {
            return bytes;
        }
        byte[] result = new byte[bytes.length - 1];
        System.arraycopy(bytes, 1, result, 0, result.length);
        return result;
    }

    public void setKeys(byte[] authKeyId, byte[] signKeyId, byte[] decKeyId,
            RSAPrivateCrtKey authKey, RSAPrivateCrtKey signKey,
            RSAPrivateCrtKey decKey) throws CardServiceException {

        byte[][] keyIds = new byte[][] { authKeyId, signKeyId, decKeyId };

        byte[] apdu = new byte[6 + authKeyId.length];
        apdu[1] = INS_PUTDATA;
        apdu[2] = 0x01;

        for (int i = 0; i < keyIds.length; i++) {
            apdu[2] = (byte) (0x61 + i);
            apdu[4] = (byte) (keyIds[i].length & 0xff);
            System.arraycopy(keyIds[i], 0, apdu, 5, keyIds[i].length);
            CommandAPDU c = new CommandAPDU(apdu);
            ResponseAPDU r = service.transmit(c);
            checkSW(r, "setKeys1 failed: ");
        }

        byte[][][] keys = new byte[][][] {
                { gb(authKey.getModulus()), gb(authKey.getPublicExponent()),
                        gb(authKey.getPrimeP()), gb(authKey.getPrimeQ()),
                        gb(authKey.getPrimeExponentP()),
                        gb(authKey.getPrimeExponentQ()),
                        gb(authKey.getCrtCoefficient()) },
                { gb(signKey.getModulus()), gb(signKey.getPublicExponent()),
                        gb(signKey.getPrimeP()), gb(signKey.getPrimeQ()),
                        gb(signKey.getPrimeExponentP()),
                        gb(signKey.getPrimeExponentQ()),
                        gb(signKey.getCrtCoefficient()) },
                { gb(decKey.getModulus()), gb(decKey.getPublicExponent()),
                        gb(decKey.getPrimeP()), gb(decKey.getPrimeQ()),
                        gb(decKey.getPrimeExponentP()),
                        gb(decKey.getPrimeExponentQ()),
                        gb(decKey.getCrtCoefficient()) } };

        for (int keyId = 0; keyId < 3; keyId++) {
            for (int keyPart = 0; keyPart < 7; keyPart++) {
                byte[] keyData = keys[keyId][keyPart];
                apdu = new byte[6 + keyData.length];
                apdu[1] = INS_PUTDATA;
                apdu[2] = (byte) (keyId + 0x64);
                apdu[3] = (byte) (keyPart + 0x81);
                apdu[4] = (byte) keyData.length;
                System.arraycopy(keyData, 0, apdu, 5, keyData.length);
                CommandAPDU c = new CommandAPDU(apdu);
                ResponseAPDU r = service.transmit(c);
                checkSW(r, "setKeys2 failed: ");
            }
        }

    }

    public void setCertificate(int fid, X509Certificate cert, boolean pin)
            throws CardServiceException {
        try {
            byte[] certBytes = cert.getEncoded();
            createFile(fid, certBytes.length, pin);
            selectFile((short) fid);
            int blockSize = 128;
            short offset = 0;
            while (offset < certBytes.length) {
                if (offset + blockSize > certBytes.length) {
                    blockSize = certBytes.length - offset;
                }
                writeFile(certBytes, offset, (byte) blockSize, offset);
                offset += blockSize;
            }
        } catch (Exception e) {
            e.printStackTrace();
            checkSW(new ResponseAPDU(new byte[] { 0x6F, 0x00 }),
                    "setCertificate failed: ");
        }
    }

}
