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
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/** 
 * A structure to store ISO7816-15 PasswordAttributes objects.
 * Does not yet fully implement the specification.
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 *
 */
public class PasswordAttributes {

    public static final byte FLAG_CASE_SENSITIVE = 0;

    public static final byte FLAG_LOCAL = 1;

    public static final byte FLAG_CHANGE_DISABLED = 2;

    public static final byte FLAG_UNBLOCK_DISABLED = 3;

    public static final byte FLAG_INITIALIZED = 4;

    public static final byte FLAG_NEEDS_PADDING = 5;

    public static final byte FLAG_UNBLOCKING_PASSWORD = 6;

    public static final byte FLAG_SO_PASSWORD = 7;

    public static final byte FLAG_DISABLE_ALLOWED = 8;

    public static final byte FLAG_INTEGRITY_PROTECTED = 9;

    public static final byte FLAG_CONF_PROTECTED = 10;

    public static final byte FLAG_EXCHANGE_REF_DATA = 11;

    public static final int TYPE_BCD = 0;

    public static final int TYPE_ASCII_NUM = 1;

    private byte[] flags;

    private int type;

    private int minLength;

    private int storedLength;

    public PasswordAttributes(byte[] flags, int type, int minLength,
            int storedLength) {
        this.flags = flags;
        this.type = type;
        this.minLength = minLength;
        this.storedLength = storedLength;
    }

    public PasswordAttributes(InputStream in) {
        throw new NotImplementedException();
    }

    public DERObject getDERObject() {
        DERBitString flags = new DERBitString(CommonObjectAttributes
                .encodeBits(this.flags), CommonObjectAttributes
                .getPad(this.flags));
        DEREnumerated type = new DEREnumerated(this.type);
        DERInteger minLength = new DERInteger(this.minLength);
        DERInteger storedLength = new DERInteger(this.storedLength);
        return new DERSequence(new ASN1Encodable[] { flags, type, minLength,
                storedLength });
    }

}
