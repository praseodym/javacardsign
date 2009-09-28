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
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

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

    static final byte INS_GENERATE = (byte) 0x46;

    /** File IDs for ceriticates */
    public static int CA_CERT_FID = 0x4101;

    public static int USER_AUTH_CERT_FID = 0x4102;

    public static int USER_SIGN_CERT_FID = 0x4103;

    public static int USER_DEC_CERT_FID = 0x4104;

    /**
     * The hierarchical structure for the file system in our applet. The data is
     * as follows, concatenated in sequence:
     * 
     * byte 0: -1/0 -1 for DF, 0 for EF byte 1, 2: fid msb, fid lsb byte 3:
     * index to the parent in this array, -1 of root node byte 4: for EF the SFI
     * of this file for DF number of children nodes, the list of indexes to the
     * children follow.
     * 
     */
    public static final byte[] fileStructure = { -1, 0x3F, 0x00, -1, 2, 7, 12, // MF
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
     * Set the historical bytes on the card. The PKI applet needs to be default
     * selectable for that.
     * 
     * @param histBytes
     *            the array with historical bytes to be set
     * @throws CardServiceException
     *             on error
     */
    public void setHistoricalBytes(byte[] histBytes)
            throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, INS_PUTDATA, 0x67, 0, histBytes);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "setHistoricalBytes failed: ");
    }

    /**
     * Set the default PUC on the card.
     * 
     * @throws CardServiceException
     *             on error
     */
    public void setPUC() throws CardServiceException {
        setPUC(DEFAULT_PUC);
    }

    /**
     * Set the given PUC on the card.
     * 
     * @param puc
     *            the PUC string
     * @throws CardServiceException
     *             on errors
     */
    public void setPUC(String puc) throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, INS_CHANGEREFERENCEDATA, 0x01, 0x00,
                puc.getBytes());
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "setPUC failed: ");
    }

    /**
     * Set the personalisation state of the applet.
     * 
     * @param state
     *            the state, valid values are: 1 initial 2 prepersonalised
     *            (keys, certs loaded, no PIN set) 3 personalised
     * @throws CardServiceException
     *             on error
     */
    public void setState(byte state) throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, INS_PUTDATA, 0x68, state);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "setState failed: ");
    }

    /**
     * Create a file in the applet. Note that the file system structure has to
     * be established first.
     * 
     * @param fid
     *            the ID of the file to create
     * @param length
     *            the required length of the file
     * @param pin
     *            whether the reading of the file should be PIN protected
     * @throws CardServiceException
     *             on error
     */
    public void createFile(int fid, int length, boolean pin)
            throws CardServiceException {
        byte[] data = { (byte) (fid >> 8), (byte) (fid & 0xFF),
                (byte) (length >> 8), (byte) (length & 0xFF),
                (byte) (pin ? 0x01 : 0x00) };
        CommandAPDU c = new CommandAPDU(0, INS_CREATEFILE, 0, 0, data);
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "createFile failed: ");
    }

    /**
     * Write a piece of data to the file in the applet. Note: for most of the
     * files that we write one call is sufficient (the files are small). For
     * bigger files a sequence is needed, eg. for certificate files.
     * 
     * @param data
     *            the data to be written array
     * @param dOffset
     *            offset to that array
     * @param dLen
     *            length of the data to be written
     * @param fOffset
     *            offset in the file in the applet
     * @throws CardServiceException
     *             on error
     */
    public void writeFile(byte[] data, short dOffset, int dLen, short fOffset)
            throws CardServiceException {
        ByteArrayOutputStream apduData = new ByteArrayOutputStream();
        apduData.write(data, dOffset, dLen);
        CommandAPDU c = new CommandAPDU(0, INS_WRITEBINARY,
                (byte) (fOffset >> 8), (byte) (fOffset & 0xFF), apduData
                        .toByteArray());
        ResponseAPDU r = service.transmit(c);
        checkSW(r, "writeFile failed: ");
    }

    /**
     * Initialises the applet data and files. After this call the applet is in
     * prepersonalised state (2). The file contents according to ISO7816-15
     * structres are created and put into corresponding files on the card.
     * 
     * @param caCert
     *            CA certificate
     * @param userAuthCertificate
     *            User authentication certificate
     * @param userSignCertificate
     *            User signing certificate
     * @param userDecCertificate
     *            User decryption certificate
     * @param authKey
     *            the user private key for authentication
     * @param signKey
     *            the user private key for signing
     * @param decKey
     *            the user private key for decryption
     * @param authKeyId
     *            the user authentication key ID
     * @param signKeyId
     *            the user signing key ID
     * @param decKeyId
     *            the user decryption key ID
     * @param pucData
     *            the PUC data
     * @throws CardServiceException
     *             on errors
     */
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
            writeFile(efPrkDContents, (short) 0, efPrkDContents.length,
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
            writeFile(cdContents, (short) 0, cdContents.length, (short) 0);

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
            writeFile(aodContents, (short) 0, aodContents.length, (short) 0);
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
            writeFile(odContents, (short) 0, odContents.length, (short) 0);
            // TODO: Radboud OID?
            ElementaryFileDIR efDIR = new ElementaryFileDIR(PKIAID,
                    "PKI Applet", new byte[] { 0x3F, 0x00, 0x50, 0x15 },
                    OID_RSA + ".50");
            byte[] efDirContents = efDIR.getEncoded();
            createFile(0x2F00, efDirContents.length, false);
            selectFile((short) 0x2F00);
            writeFile(efDirContents, (short) 0, efDirContents.length, (short) 0);

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
            AlgorithmInfo al5 = new AlgorithmInfo(5, 5,
                    new byte[] { AlgorithmInfo.OP_COMPUTE_SIGNATURE },
                    OID_RSA, (byte) 5);

            ElementaryFileCIAInfo efCia = new ElementaryFileCIAInfo(
                    ElementaryFileCIAInfo.V2, "Radboud", new byte[] {
                            ElementaryFileCIAInfo.CARD_FLAG_READ_ONLY,
                            ElementaryFileCIAInfo.CARD_AUTH_REQUIRED,
                            ElementaryFileCIAInfo.CARD_PRN_GENERATION },
                    new AlgorithmInfo[] { al1, al2, al3, al4, al5 });

            byte[] ciaContents = efCia.getDERObject().getDEREncoded();
            createFile(0x5032, ciaContents.length, false);
            selectFile((short) 0x5032);
            writeFile(ciaContents, (short) 0, ciaContents.length, (short) 0);

            setPUC(pucData);
            setState((byte) 2);
        } catch (Exception e) {
            throw new CardServiceException("" + e.toString());
        }
    }

    /**
     * Creates the file structure in the applet. Note that this does not create
     * the file arrays in the card, only informs the applet about the intended
     * file structure (the file system tree and file IDs)
     * 
     * @param fs
     *            the array with the file structure information, see
     *            {@link #fileStructure}.
     * @throws CardServiceException
     *             on errors
     */
    private void createFileStructure(byte[] fs) throws CardServiceException {
        CommandAPDU c = new CommandAPDU(0, INS_PUTDATA, 0x69, 0x00, fs);
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

    /**
     * Set the private keys in the applet
     * 
     * @param authKeyId
     *            authentication key id
     * @param signKeyId
     *            signing key id
     * @param decKeyId
     *            decryption key id
     * @param authKey
     *            authentication key
     * @param signKey
     *            signing key
     * @param decKey
     *            decryption key
     * @throws CardServiceException
     *             on errors
     */
    public void setKeys(byte[] authKeyId, byte[] signKeyId, byte[] decKeyId,
            RSAPrivateCrtKey authKey, RSAPrivateCrtKey signKey,
            RSAPrivateCrtKey decKey) throws CardServiceException {

        byte[][] keyIds = new byte[][] { authKeyId, signKeyId, decKeyId };

        for (int i = 0; i < keyIds.length; i++) {
            CommandAPDU c = new CommandAPDU(0, INS_PUTDATA, (byte) (0x61 + i),
                    0, keyIds[i]);
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
                CommandAPDU c = new CommandAPDU(0, INS_PUTDATA,
                        (byte) (keyId + 0x64), (byte) (keyPart + 0x81), keyData);
                ResponseAPDU r = service.transmit(c);
                checkSW(r, "setKeys2 failed: ");
            }
        }

    }

    /**
     * Generate the set of private keys on the card.
     * 
     * @param authKeyId
     *            the id of the authentication key
     * @param signKeyId
     *            the id of the signing key
     * @param decKeyId
     *            the id of the decryption key
     * @return the map with the corresponding public keys indexed by the key
     *         identifiers
     * @throws CardServiceException
     *             on errors
     */
    public Map<byte[], PublicKey> generateKeys(byte[] authKeyId,
            byte[] signKeyId, byte[] decKeyId) throws CardServiceException {
        byte[][] keyIds = new byte[][] { authKeyId, signKeyId, decKeyId };
        int[] modes = { MSE_AUTH, MSE_SIGN, MSE_DEC };
        Map<byte[], PublicKey> result = new HashMap<byte[], PublicKey>();
        for (int i = 0; i < keyIds.length; i++) {
            CommandAPDU c = new CommandAPDU(0, INS_PUTDATA, (byte) (0x61 + i),
                    0, keyIds[i]);
            ResponseAPDU r = service.transmit(c);
            checkSW(r, "generateKeys failed: ");
        }
        for (int i = 0; i < keyIds.length; i++) {
            manageSecurityEnvironment(modes[i], keyIds[i]);
            result.put(keyIds[i], generateAssymetricKeyPair());
        }
        return result;
    }

    /**
     * Manage security environment - prepare the card for the upcoming generate
     * key operation.
     * 
     * @param mode
     *            MSE_AUTH, MSE_SIGN, or MSE_DEC
     * @param keyId
     *            the id of the key on the card.
     * 
     * @throws CardServiceException
     *             on errors
     */
    public void manageSecurityEnvironment(int mode, byte[] keyId)
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
     * Generate assymetric key pair. This is for the on-card key generation.
     * 
     * @return the public key counterpart of the generated private key
     * @throws CardServiceException
     *             on errors
     */
    public PublicKey generateAssymetricKeyPair() throws CardServiceException {
        try {
            CommandAPDU c = new CommandAPDU(0, INS_GENERATE, 0x80, 0);
            ResponseAPDU r = service.transmit(c);
            checkSW(r, "manageSecureEnvironment failed: ");
            byte[] mod = new byte[128];
            byte[] exp = new byte[3];
            System.arraycopy(r.getData(), 3, mod, 0, 128);
            System.arraycopy(r.getData(), 128 + 3 + 2, exp, 0, 3);
            KeySpec spec = new RSAPublicKeySpec(new BigInteger(1, mod),
                    new BigInteger(1, exp));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new CardServiceException(ex.getMessage());
        }
    }

    /**
     * Write one certificate to the file system in the applet. Initialises the
     * given file.
     * 
     * @param fid
     *            the file ID
     * @param cert
     *            the certificate to be written
     * @param pin
     *            true if the file should be PIN protected on reading
     * @throws CardServiceException
     *             on errors
     */
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
                writeFile(certBytes, offset, blockSize, offset);
                offset += blockSize;
            }
        } catch (Exception e) {
            e.printStackTrace();
            checkSW(new ResponseAPDU(new byte[] { 0x6F, 0x00 }),
                    "setCertificate failed: ");
        }
    }
}
