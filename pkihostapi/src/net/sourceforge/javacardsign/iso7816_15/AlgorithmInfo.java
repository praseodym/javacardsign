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
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/** 
 * A structure to store ISO7816-15 AlgorigthmInfo objects.
 * Does not yet fully implement the specification.
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 *
 */
public class AlgorithmInfo {

    public static final byte OP_COMPUTE_CHECKSUM = 0;

    public static final byte OP_COMPUTE_SIGNATURE = 1;

    public static final byte OP_VERIFY_CHECKSUM = 2;

    public static final byte OP_VERIFY_SIGNATURE = 3;

    public static final byte OP_ENCIPHER = 4;

    public static final byte OP_DECIPHER = 5;

    public static final byte OP_HASH = 6;

    public static final byte OP_GENERATE_KEY = 7;

    private int reference;

    private int internalIdentifier;

    private byte[] operations;

    private String objectId;

    private byte algId;

    public AlgorithmInfo(int reference, int internalIdentifier,
            byte[] operations, String objectId, byte algId) {
        this.reference = reference;
        this.internalIdentifier = internalIdentifier;
        this.operations = operations;
        this.objectId = objectId;
        this.algId = algId;
    }

    public AlgorithmInfo(InputStream in) {
        throw new NotImplementedException();
    }

    public DERObject getDERObject() {
        DERInteger reference = new DERInteger(this.reference);
        DERInteger internalIdentifier = new DERInteger(this.internalIdentifier);
        DERBitString operations = new DERBitString(CommonObjectAttributes
                .encodeBits(this.operations), CommonObjectAttributes
                .getPad(this.operations));
        DERObjectIdentifier objectId = new DERObjectIdentifier(this.objectId);
        DERInteger algId = new DERInteger(this.algId);
        return new DERSequence(new ASN1Encodable[] { reference,
                internalIdentifier, new DERNull(), operations, objectId, algId });
    }

}
