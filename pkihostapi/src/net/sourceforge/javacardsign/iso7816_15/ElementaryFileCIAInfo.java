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
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

public class ElementaryFileCIAInfo {

    public static final int V1 = 0;

    public static final int V2 = 1;

    public static final byte CARD_FLAG_READ_ONLY = 0;

    public static final byte CARD_AUTH_REQUIRED = 1;

    public static final byte CARD_PRN_GENERATION = 2;

    private int version;

    private String manufacturerId;

    private byte[] cardFlags;

    private AlgorithmInfo[] algorithmInfos;

    public ElementaryFileCIAInfo(int version, String manufacturerId,
            byte[] cardFlags, AlgorithmInfo[] algorithmInfos) {
        this.version = version;
        this.manufacturerId = manufacturerId;
        this.cardFlags = cardFlags;
        this.algorithmInfos = algorithmInfos;
    }

    public ElementaryFileCIAInfo(InputStream in) {
        throw new NotImplementedException();
    }

    public DERObject getDERObject() {
        DERInteger version = new DERInteger(this.version);
        DERUTF8String manufacturerId = new DERUTF8String(this.manufacturerId);
        DERBitString cardFlags = new DERBitString(CommonObjectAttributes
                .encodeBits(this.cardFlags), CommonObjectAttributes
                .getPad(this.cardFlags));
        ASN1Encodable[] algs = new ASN1Encodable[algorithmInfos.length];
        for (int i = 0; i < algs.length; i++) {
            algs[i] = this.algorithmInfos[i].getDERObject();
        }
        DERSequence algorithmInfos = new DERSequence(algs);
        return new DERSequence(new ASN1Encodable[] { version, manufacturerId,
                cardFlags, new DERTaggedObject(2, algorithmInfos) });
    }

}
