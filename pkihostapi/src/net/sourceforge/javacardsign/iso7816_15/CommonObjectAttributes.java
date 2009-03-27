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

package net.sourceforge.javacardsign.iso7816_15;

import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class CommonObjectAttributes {

    public static final int FLAG_PRIVATE = 0x00;

    public static final int FLAG_MODIFIABLE = 0x01;

    public static final int FLAG_INTERNAL = 0x02;

    private String label;

    private byte authId;

    private byte[] flags;

    public CommonObjectAttributes(String label, byte authId, byte[] flags) {
        this.label = label;
        this.authId = authId;
        this.flags = flags;
    }

    public CommonObjectAttributes(String label, byte[] flags) {
        this.label = label;
        this.authId = -1;
        this.flags = flags;
    }

    public CommonObjectAttributes(InputStream in) {
        throw new NotImplementedException();
    }

    public DERObject getDERObject() {
        DERUTF8String label = new DERUTF8String(this.label);
        DERBitString flags = new DERBitString(encodeBits(this.flags),
                getPad(this.flags));
        if (authId != -1) {
            DEROctetString authId = new DEROctetString(
                    new byte[] { this.authId });
            return new DERSequence(new ASN1Encodable[] { label, flags, authId });
        } else {
            return new DERSequence(new ASN1Encodable[] { label, flags });
        }
    }

    public static byte[] encodeBits(byte[] bitsSet) {
        if (bitsSet.length == 0) {
            return new byte[0];
        }
        int numBytes = bitsSet[bitsSet.length - 1] / 8 + 1;
        byte[] result = new byte[numBytes];
        for (int i = 0; i < bitsSet.length; i++) {
            int offset = bitsSet[i] / 8;
            int bitShift = (7 - (bitsSet[i] % 8));
            result[offset] = (byte) (result[offset] | (byte) ((0x01 << bitShift) & 0xFF));
        }
        return result;
    }

    public static int getPad(byte[] bitsSet) {
        if (bitsSet.length == 0) {
            return 0;
        }
        int num = (7 - (bitsSet[bitsSet.length - 1] % 8));
        return num;
    }

}
