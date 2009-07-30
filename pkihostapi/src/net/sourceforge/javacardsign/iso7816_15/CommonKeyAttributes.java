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

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/** 
 * A structure to store ISO7816-15 CommonKeyAttributes objects.
 * Does not yet fully implement the specification.
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 *
 */
public class CommonKeyAttributes {
    public static final int USAGE_ENC = 0x00;

    public static final int USEAGE_DEC = 0x01;

    public static final int USEAGE_SIGN = 0x02;

    public static final int USEAGE_SIGN_RECOVER = 0x03;

    public static final int USEAGE_KEY_ENC = 0x04;

    public static final int USEAGE_KEY_DEC = 0x05;

    public static final int USEAGE_VERIFY = 0x06;

    public static final int USEAGE_VERIFY_RECOVER = 0x07;

    public static final int USEAGE_DERIVE = 0x08;

    public static final int USEAGE_NON_REP = 0x09;

    private byte[] id;

    private byte[] usage;

    public CommonKeyAttributes(byte[] id, byte[] usage) {
        this.id = id;
        this.usage = usage;
    }

    public CommonKeyAttributes(InputStream in) {
        throw new NotImplementedException();
    }

    public DERObject getDERObject() {
        DERBitString usage = new DERBitString(CommonObjectAttributes
                .encodeBits(this.usage), CommonObjectAttributes
                .getPad(this.usage));
        DEROctetString id = new DEROctetString(this.id);
        return new DERSequence(new ASN1Encodable[] { id, usage });
    }

}
