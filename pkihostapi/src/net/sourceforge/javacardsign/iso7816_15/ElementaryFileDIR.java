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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTags;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class ElementaryFileDIR {

    private byte[] aid;

    private String label;

    private byte[] dfCiaPath;

    private String providerId;

    public ElementaryFileDIR(byte[] aid, String label, byte[] dfCiaPath,
            String providerId) {
        this.aid = aid;
        this.label = label;
        this.dfCiaPath = dfCiaPath;
        this.providerId = providerId;
    }

    public ElementaryFileDIR(InputStream in) {
        throw new NotImplementedException();
    }

    public byte[] getEncoded() throws IOException {
        DERApplicationSpecific aid = new DERApplicationSpecific(15, this.aid);
        DERApplicationSpecific label = new DERApplicationSpecific(16,
                this.label.getBytes());
        DERApplicationSpecific path = new DERApplicationSpecific(17,
                this.dfCiaPath);
        DERObjectIdentifier providerId = new DERObjectIdentifier(
                this.providerId);
        DERSet ddo = new DERSet(new ASN1Encodable[] { providerId });
        byte[] tmp = new DERApplicationSpecific(false, 19, ddo).getEncoded();
        tmp[0] |= DERTags.CONSTRUCTED;
        DERObject d = new ASN1InputStream(new ByteArrayInputStream(tmp))
                .readObject();
        DERSet s = new DERSet(new ASN1Encodable[] { aid, label, path, d });
        tmp = new DERApplicationSpecific(false, 1, s).getEncoded();
        tmp[0] |= DERTags.CONSTRUCTED;
        return tmp;

    }

}
