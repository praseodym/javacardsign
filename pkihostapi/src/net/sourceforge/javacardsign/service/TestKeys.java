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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class TestKeys {

    public static final String cacertFileName = "cacert.der";

    public static final String authcertFileName = "authcert.der";

    public static final String signcertFileName = "signcert.der";

    public static final String deccertFileName = "deccert.der";

    public static final String authkeyFileName = "authkey.der";

    public static final String signkeyFileName = "signkey.der";

    public static final String deckeyFileName = "deckey.der";

    public static final byte[] AUTH_KEY_ID = new byte[] { 0x00, 0x01 };

    public static final byte[] SIGN_KEY_ID = new byte[] { 0x00, 0x02 };

    public static final byte[] DEC_KEY_ID = new byte[] { 0x00, 0x03 };

    public static final byte[] aKeyMod = Util
            .stringToByteArray("B464D0ECCE76B8827AB41E400D7BF2C39B09D32270E13803C85A70C0F1A578622A0DBF26B95168B42FEC4FA8E74944A888EC404FBC5CB9EE864FBD1246F1503798A105433F1DE7A6CCBE1A6331D1F224363FCC1F8247422494AE2F217898B3F0E5351691128A1DE208F67CBEEDDDD5304298C0FA5496AC5C8F3096DA3ECA029B");

    public static final byte[] aKeyExp = Util.stringToByteArray("010001");

    public static final byte[] aKeyPrivExp = Util
            .stringToByteArray("63CD4B115880B23FEDE6ECBD7F384DED0E3F77421CB55DAA2A146F412FEFDE146133CDC77CCB9F63E1079A62D5E2E14B64C560273D0D080900E1E8B6CDECFFF57480C715E6A763107AC281AD68BB6CF2259FE6B9CF21D776FEF8D58CC55E727C55E027713431DA26A409F57E0A44E34DE07497DB2CCF2F44414FFFD21E009641");

    public static final byte[] aKeyP = Util
            .stringToByteArray("D727CDBF627C5B571E1B2F7073537BDC2921E8C9A9AB92F5E1024370BE3D1747AADA1955899245754F88F41D818A6062D38F6D98C0D3ECE66B5AE5F3F9A2AA51");

    public static final byte[] aKeyQ = Util
            .stringToByteArray("D6A3A74736C1A5AC6E27213AE2B1C4175F3E888A09D6242076FB097D0D7ACE6B0218049BB7437606A4622092A041AE4FDF0E1FE963733EFA6F8CC31627E0372B");

    public static final byte[] aKeyDP = Util
            .stringToByteArray("3DA18C41575FD1F6598C66016B37ADD23A0219A1B2B5902A58A3025888560D961CEDCEB5FEEB64741F2D56E820D45799D78A4D55A55ECF8C8D92032EE9025C91");

    public static final byte[] aKeyDQ = Util
            .stringToByteArray("05D032E4A3E004CBB1C40F8B57BE76D0273D3B5779C2BA01C317337F9690DFEC58072C80C72AE594727951E686BEA0A8FB2297CCAB6BE0A5C9C5A736FF677C37");

    public static final byte[] aKeyPQ = Util
            .stringToByteArray("BC469C31E603B4CE390E2FDF75A068E80D68E35CCC45C46EEF0D86E89FBCD33B6F9664E726E9557B0C38FCA3FE865A0E23C15FDFEDBB64BAF6067652C699210F");

    public static final byte[] sKeyMod = Util
            .stringToByteArray("A4C9A86F7AC7090149D6F0B6DE9949C783711EEE37116AE79BB23E293A683A4A72106746F6B327ECFF6AC1AF89AE1F6D9618D470C5699502482DA241A7B941C26CC76626E66245E6CBAB931290AE812E3BCD4ADC66E76F697CB32DEE0BBEEB7F055483B5A4B9B06ADC436D39507B6E11DF3A2465A8E5D9000435D09C5CC18F75");

    public static final byte[] sKeyExp = Util.stringToByteArray("010001");

    public static final byte[] sKeyPrivExp = Util
            .stringToByteArray("78FFC1F82995205D9BD481E82547354F948A6985CD55B2C3E2255D537499B7C39641C933E84DE0D13B332E893075748A491E6E4F680580EEAE0524114590D8613750BF651412B33A5CF9994BC4B09593CE43A17A20A4642A115E0F4381D5EA0EF94BCDFD147B230F5B73437EF606239D6820DD5D45AD0DA9B41DE6EA60C4E041");

    public static final byte[] sKeyP = Util
            .stringToByteArray("CE03962E28FCE8C4FE8D2288869564CAAFE74EC6B227F9A34C2D07FE7668C38593865FE5A26EA5D8D4C30AE8239E181EB9468A874FB2831A0E918A656AE08459");

    public static final byte[] sKeyQ = Util
            .stringToByteArray("CCC5547FEE0273700B4127BF0BCF27482106BED82A73880A3B80E0D2BBC51B51B4239F5831931037AA0CE5835AB1B9D0D380F0C5B397D1D5D205B7940DCA707D");

    public static final byte[] sKeyDP = Util
            .stringToByteArray("57AF231EA6876EB359FCCC33FBC45E4FFEAA9ED6E74128799E949410746986BEB5D9BDBB49757AD55D495EBD0B5BE0BC42F38946AA5F3A79BEB5A7881F034C91");

    public static final byte[] sKeyDQ = Util
            .stringToByteArray("4F2CCD6B599FE0FAA59F5FBAE2DA0A1A3D8ADA27C2E240EB93EE54FFA652A42987396ED72EF3EA055BDEF8AF3D5612BEC7C8C74FEA0CFDB96B2782BFE0453211");

    public static final byte[] sKeyPQ = Util
            .stringToByteArray("BA3C31ACA70319A0CE814E15A7178A7C294576B44B169CC1BE00D5E5B8E7A6682F79FBE784177548F9E502AD8FDE005D719AD12AE9612C33F236E0B4CBECC59C");

    public static final byte[] dKeyMod = Util
            .stringToByteArray("D2E916D4799945412EB3682AAFA55D84BB463041B87EA48335ED751A50E57DC04E4129172B88C09AC8334EE9874D50FA13134326C4EA9C25F508E9DCC9E2F97297F0E047D6EEE8148A105ED496223D0FF7D30546BDCA5E15CA21A79F0C60D9E5F35B5FA38F0F049C36BEA4AFCFC7657F76CA0A8A882DF1AFF726586DD3C643BB");

    public static final byte[] dKeyExp = Util.stringToByteArray("010001");

    public static final byte[] dKeyPrivExp = Util
            .stringToByteArray("69B537A310BB1831DE453F2D3DD1A4F894A04E29725DCEF8907BCE587D393878BCFFFDA74643893D4AA024A9F90D704B9669EE1B2D50E5284512CD9BC278074B55BE7ED62F4C81CB467944EF3FDEE561BBCE0DB1F747B16875D06F5E9841390C055BE1090ADB7E928F343654E1C6B052CBFB244B68BE3C6367CD9E73C7E3EAC9");

    public static final byte[] dKeyP = Util
            .stringToByteArray("F5D8A611A770DF7B60861683353B605B0DD5261B16257F0586688A4CCDEBF64D763F61800BBADB0CA6D7E2C881E77A391CBA9EB73F8E536E82B7844B4AB9CAE5");

    public static final byte[] dKeyQ = Util
            .stringToByteArray("DB9F0FD4FB36EA4E4B366944018B6CA2D2C89F0932F591E1981542157EB39A493F346649642A52862C24C88D0362C053E318F7620C6F79B4BAE749476F96CA1F");

    public static final byte[] dKeyDP = Util
            .stringToByteArray("4FBF7E675DA46CAA2DEE712110C47906305F8323E83433970C399F1B38F5210991A10FB4A49971731230179DA91DF874CC4FF12A4A5095D9D447497FCEF6A3CD");

    public static final byte[] dKeyDQ = Util
            .stringToByteArray("C6389F627CC6C8DD9796E9959ECB476702565EEC3F99536CC9064ED9F5BC87019B51610CD6A2384FAF6217BCE69467C08F15469AB15C9FFD9640106CB073E9C3");

    public static final byte[] dKeyPQ = Util
            .stringToByteArray("BB193D20F7D1C7D1A5CCAC441AE2E2ECC9694CD6C65D8519B5A8CF8B451501628A69CF174CE68377E738F04E7701B38BD2BB0FC2B0D1CD6A2A3851419646A827");

    public static RSAPublicKey getAuthPublicKey() {
        try {
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(1,
                    aKeyMod), new BigInteger(1, aKeyExp));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static RSAPublicKey getSignPublicKey() {
        try {
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(1,
                    sKeyMod), new BigInteger(1, sKeyExp));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static RSAPublicKey getDecPublicKey() {
        try {
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(1,
                    dKeyMod), new BigInteger(1, dKeyExp));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static RSAPrivateKey getAuthPrivateKey() {
        try {
            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                    new BigInteger(1, aKeyMod), new BigInteger(1, aKeyExp),
                    new BigInteger(1, aKeyPrivExp), new BigInteger(1, aKeyP),
                    new BigInteger(1, aKeyQ), new BigInteger(1, aKeyDP),
                    new BigInteger(1, aKeyDQ), new BigInteger(1, aKeyPQ));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static RSAPrivateKey getSignPrivateKey() {
        try {
            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                    new BigInteger(1, sKeyMod), new BigInteger(1, sKeyExp),
                    new BigInteger(1, sKeyPrivExp), new BigInteger(1, sKeyP),
                    new BigInteger(1, sKeyQ), new BigInteger(1, sKeyDP),
                    new BigInteger(1, sKeyDQ), new BigInteger(1, sKeyPQ));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static RSAPrivateKey getDecPrivateKey() {
        try {
            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                    new BigInteger(1, dKeyMod), new BigInteger(1, dKeyExp),
                    new BigInteger(1, dKeyPrivExp), new BigInteger(1, dKeyP),
                    new BigInteger(1, dKeyQ), new BigInteger(1, dKeyDP),
                    new BigInteger(1, dKeyDQ), new BigInteger(1, dKeyPQ));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

}
