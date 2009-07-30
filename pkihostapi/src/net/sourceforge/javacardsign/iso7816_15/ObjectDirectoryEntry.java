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
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/** 
 * A structure to store ISO7816-15 ObjectDirectoryEntry objects.
 * Does not yet fully implement the specification.
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 *
 */
public class ObjectDirectoryEntry {

    public static final int TAG_PRIVATE_KEYS = 0;

    public static final int TAG_PUBLIC_KEYS = 1;

    public static final int TAG_TRUSTED_PUBLIC_KEYS = 2;

    public static final int TAG_SECRET_KEYS = 3;

    public static final int TAG_CERTIFICATES = 4;

    public static final int TAG_TRUSTED_CERTIFICATES = 5;

    public static final int TAG_USEFUL_CERTIFICATES = 6;

    public static final int TAG_DATA_CONTAINER_OBJECT = 7;

    public static final int TAG_AUTH_OBJECTS = 8;

    private int tag;

    private int fid;

    public ObjectDirectoryEntry(int tag, int fid) {
        this.tag = tag;
        this.fid = fid;
    }

    public ObjectDirectoryEntry(InputStream in) {
        throw new NotImplementedException();
    }

    public DERObject getDERObject() {
        byte[] p = new byte[2];
        p[0] = (byte) (this.fid >> 8 & 0xFF);
        p[1] = (byte) (this.fid & 0xFF);
        DERSequence path = new DERSequence(
                new ASN1Encodable[] { new DEROctetString(p) });
        return new DERTaggedObject(tag, path);
    }
}
