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

import java.security.cert.Certificate;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] pkcs1Encrypt(PublicKey key, byte[] text) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            return c.doFinal(text);
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean pkcs1DecryptCompare(PublicKey key, byte[] text,
            byte[] shouldbe) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.DECRYPT_MODE, key);
            text = c.doFinal(text);
            return compare(text, shouldbe);
        } catch (Exception e) {
            return false;
        }
    }

    public static byte[] pkcs1Sign(PrivateKey key, byte[] text) {
        try {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            return c.doFinal(text);
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean compare(byte[] t1, byte[] t2) {
        if (t1 == null || t2 == null || t1.length != t2.length)
            return false;
        for (int i = 0; i < t1.length; i++) {
            if (t1[i] != t2[i])
                return false;
        }
        return true;
    }

    public static boolean pkcs1Verify(PublicKey key, byte[] text,
            byte[] signature, boolean sha256) {
        String algName = sha256 ? "SHA256withRSA" : "SHA1withRSA";
        try {
            Signature s = Signature.getInstance(algName);
            s.initVerify(key);
            s.update(text);
            return s.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] pssSign(PrivateKey key, byte[] text, boolean doHash) {
        return pssSign(null, key, text, doHash);
    }

    public static byte[] pssSign(byte[] salt, PrivateKey key, byte[] text,
            boolean doHash) {

        byte[] t = ((RSAPrivateKey) key).getModulus().toByteArray();
        int emLen = (t.length % 8 == 0) ? t.length : (t.length - 1);

        boolean repeat = false;
        if (salt == null) {
            repeat = true;
            salt = new byte[20];
        }
        SecureRandom sr = new SecureRandom();

        try {
            while (true) {
                if (repeat) {
                    sr.nextBytes(salt);
                }
                try {
                    byte[] output = pssPad(salt, text, doHash, emLen);
                    Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                    byte[] res = cipher.doFinal(output);
                    return res;
                } catch (BadPaddingException e) {
                    if (!repeat)
                        return null;
                }
            }
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean pssVerify(PublicKey key, byte[] text, byte[] signature) {
        try {
            // The two algorithms are the same
            // Signature s = Signature.getInstance("SHA1withRSA/PSS");
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.initVerify(key);
            s.update(text);
            return s.verify(signature);
        } catch (Exception e) {
            return false;
        }

    }

    public static byte[] getHash(String algName, byte[] text, boolean derWrapped) {
        try {
            MessageDigest md = MessageDigest.getInstance(algName);
            byte[] data = md.digest(text);
            if (derWrapped) {
                String oid = algName.equals("SHA1") ? PKIService.OID_SHA1
                        : PKIService.OID_SHA256;
                DigestInfo di = new DigestInfo(new AlgorithmIdentifier(
                        new DERObjectIdentifier(oid)), data);
                return di.getDEREncoded();
            } else {
                return data;
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] pssPad(byte[] salt, byte[] text, boolean doHash,
            int emLen) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");

            byte[] h1 = null;
            if (doHash) {
                h1 = md.digest(text);
            } else {
                h1 = text; // text is already the hash to be signed
            }
            int hLen = h1.length;
            int sLen = 20;
            int psLen = emLen - sLen - hLen - 2;

            byte[] output = new byte[emLen];

            md.update(output, 0, (short) 8);
            md.update(h1, 0, hLen);
            byte[] tmpHash = md.digest(salt);
            output[psLen] = (byte) 0x01;

            int hOffset = emLen - hLen - 1;
            System.arraycopy(tmpHash, 0, output, hOffset, hLen);
            System.arraycopy(salt, 0, output, psLen + 1, salt.length);
            output[emLen - 1] = (byte) 0xbc;

            int counter = 0;
            int outOffset = 0;
            byte[] c = new byte[4];
            while (outOffset < hOffset) {
                c[c.length - 1] = (byte) counter;
                md.update(output, hOffset, hLen);
                tmpHash = md.digest(c);
                if (outOffset + hLen > hOffset) {
                    hLen = hOffset - outOffset;
                }
                for (int i = 0; i < hLen; i++) {
                    output[outOffset++] ^= tmpHash[i];
                }
                counter++;
            }
            return output;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PrivateKey readPrivateKeyFromDER(String fileName) {
        try {
            InputStream fl = fullStream(fileName);
            byte[] key = new byte[fl.available()];
            KeyFactory kf = KeyFactory.getInstance("RSA");
            fl.read(key, 0, fl.available());
            fl.close();
            PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec(key);
            PrivateKey privK = kf.generatePrivate(keysp);
            return privK;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static X509Certificate readCertFromDER(String fileName) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            InputStream certstream = fullStream(fileName);
            Certificate c = cf.generateCertificate(certstream);
            return (X509Certificate) c;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static InputStream fullStream(String fname) throws IOException {
        DataInputStream dis = new DataInputStream(new FileInputStream(fname));
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return bais;
    }

}
