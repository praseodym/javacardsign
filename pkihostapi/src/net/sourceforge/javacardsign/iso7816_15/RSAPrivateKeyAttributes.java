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
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class RSAPrivateKeyAttributes {
    private int path;

    private int modSize;

    public RSAPrivateKeyAttributes(int path, int modSize) {
        this.path = path;
        this.modSize = modSize;
    }

    public RSAPrivateKeyAttributes(InputStream in) {
        throw new NotImplementedException();
    }

    public DERObject getDERObject() {
        byte[] p = new byte[2];
        p[0] = (byte) (this.path >> 8 & 0xFF);
        p[1] = (byte) (this.path & 0xFF);
        DERSequence path = new DERSequence(
                new ASN1Encodable[] { new DEROctetString(p) });
        DERInteger modSize = new DERInteger(this.modSize);
        return new DERSequence(new ASN1Encodable[] { path, modSize });
    }

}
