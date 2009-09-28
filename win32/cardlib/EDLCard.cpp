#include "stdafx.h"
#include "EDLCard.h"
#include "helperMacro.h"
#include <algorithm>
#include "wincrypt.h"

// select the PKI applet
void EDLCard::connectToApplet()
{
	//AID: A0 00 00 00 63 50 4B 43 53 2D 31 35
	byte cmdMF[]= {0x00, 0xA4, 0x04, 0x00, 0x0C, 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 }; 
	ByteVec code;
	code = execute( MAKEVECTOR(cmdMF));
}

// not used
void EDLCard::reconnectWithT0()
{
	if (mConnection->mOwnConnection) 
	{
		uint prev = mConnection->mIndex;
		delete mConnection;
		connect(prev,true);
	}
	else 
	{
		mConnection = mManager.reconnect(mConnection,true);
	}
}

// not used
void EDLCard::checkProtocol()
{
	try 
	{
		selectMF(true);
	} 
	catch(CardError &ce) 
	{
		if (ce.SW1 != 0x6A || ce.SW2 != 0x87 ) throw ce;
		reconnectWithT0();
	}
}

// returns the raw bytes of a file on the card
// 0x4101 CA CERT?
// 0x4102 Auth CERT length: 0x2F8
// 0x4103 Sign CERT?
// 0x4104 Dec CERT?
ByteVec EDLCard::getFile(int fileId, int length ) {
	FCI fileInfo = selectEF(fileId,true); // ignoreFCI == true so fileinfo is all 0's
	fileInfo.fileLength = length;

	return readEF(fileInfo.fileLength);

	/* // old case when a pin was still needed
	try
	{
		return readEF(fileInfo.fileLength);
	}
	catch(CardError & err)
	{
		if(err.SW1 == 0x69 && err.SW2 == 0x82) // PIN NO LONGER NEEDED
		{
			// REPLACE WITH AN ACTUAL ENTER PIN DIALOG (only possible on vista and higher?)
			byte insVerifyCmd[] = {0x00, 0x20, 0x00, 0x00, 0x04, 0x31, 0x32, 0x33, 0x34};
			ByteVec reply = execute(MAKEVECTOR(insVerifyCmd));
		}
		return readEF(fileInfo.fileLength);
	}*/
}

// returns the raw bytes of the CA Cert
ByteVec EDLCard::getCaCert() {
	//return getFile(0x4101, 0x2F8);
	return getFile(0x4101, 0xFFFF);
}

// returns the raw bytes of the Auth Cert
ByteVec EDLCard::getAuthCert() {
	//return getFile(0x4102, 0x2F8);
	return getFile(0x4102, 0xFFFF);
}

// returns the raw bytes of the Sign Cert
ByteVec EDLCard::getSignCert() {
	//return getFile(0x4103, 0x2F8);
	return getFile(0x4103, 0xFFFF);
}

// returns the raw bytes of the Dec Cert
ByteVec EDLCard::getDecCert() {
	//return getFile(0x4104, 0x2F8);
	return getFile(0x4104, 0xFFFF);
}

// get a challenge of certain length from the card (not used)
ByteVec EDLCard::getChallenge(byte length)
{
	if(length == 256) length = 0;
	byte cmdMF[]= {0x00, 0x84, 0x00, 0x00, length }; 
	ByteVec code;
	code = execute( MAKEVECTOR(cmdMF));

	return code;
}

ByteVec EDLCard::signData(ByteVec data, std::string pin)
{
	// manage security environment for SIGN - SHA1 PKCS1
	//byte cmdManageSecurityEnvironment[] = {0x00, 0x22, 0x41, 0xB6, 0x07, 0x84, 0x02, 0x00, 0x02, 0x80, 0x01, 0x02};
	byte cmdManageSecurityEnvironment[] = {0x00, 0x22, 0x41, 0xB6, 0x07, 0x84, 0x02, 0x00, 0x02, 0x80, 0x01, 0x05};
	// manage security environment for PSS
	//byte cmdManageSecurityEnvironment[] = {0x00, 0x22, 0x41, 0xB6, 0x07, 0x84, 0x02, 0x00, 0x02, 0x80, 0x01, 0x04};
	ByteVec reply = execute ( MAKEVECTOR(cmdManageSecurityEnvironment));
	
	if(authPin(pin) != 0xFF)
		throw new std::runtime_error("wrong pin for signing!");

	// headers in comment are from the esteid project maybe add support for sha256 header? (md5 is not supported by edl)
	//byte hashHdMD5[] = {0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,0x04,0x10};
	//byte hashHdSHA1[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14 };
	byte hashHdSHA1[] =   {0x30,0x1F,0x30,0x07,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x04,0x14};
	ByteVec header = MAKEVECTOR(hashHdSHA1);

	try
	{
		byte cmdCalculateSignature[] = {0x00, 0x2A, 0x9E, 0x9A};
		ByteVec cmd = MAKEVECTOR(cmdCalculateSignature);

		//cmd.push_back(data.size()+header.size());
		cmd.push_back(data.size());
		//cmd.insert(cmd.end(), header.begin(), header.end());

		cmd.insert(cmd.end(), data.begin(), data.end());
		
		reply = execute ( cmd);
	}
	catch(CardError & err)
	{
		throw err;
	}

	return reply;
}

// sign data
ByteVec EDLCard::internalAuth(ByteVec data, std::string pin)
{
	// manage security environment for internal auth
	byte cmdManageSecurityEnvironment[] = {0x00, 0x22, 0x41, 0xA4, 0x07, 0x84, 0x02, 0x00, 0x01, 0x80, 0x01, 0x01};
	ByteVec reply = execute ( MAKEVECTOR(cmdManageSecurityEnvironment));
	
	if(authPin(pin) != 0xFF)
		throw new std::runtime_error("wrong pin for signing!");

	try
	{
		byte cmdInternalAuthenticate[] = {0x00, 0x88, 0x00, 0x00};
		ByteVec cmd = MAKEVECTOR(cmdInternalAuthenticate);

		cmd.push_back(data.size());
		cmd.insert(cmd.end(), data.begin(), data.end());
		
		reply = execute ( cmd);
	}
	catch(CardError & err)
	{
		throw err;
	}

	return reply;
}

// decrypt a given byte buffer
ByteVec EDLCard::rsaDecrypt(ByteVec data, std::string pin)
{
	byte cmdManageSecurityEnvironment[] = {0x00, 0x22, 0x41, 0xB8, 0x07, 0x84, 0x02, 0x00, 0x03, 0x80, 0x01, 0x01};
	ByteVec reply = execute ( MAKEVECTOR(cmdManageSecurityEnvironment));
	
	if(authPin(pin) != 0xFF)
		throw new std::runtime_error("wrong pin for decrypting!");

	byte decryptCmd[] = {0x00, 0x2A, 0x80, 0x86};
	ByteVec cmd = MAKEVECTOR( decryptCmd);

	cmd.push_back(data.size());
	cmd.insert(cmd.end(), data.begin(), data.end());

	reply = execute( cmd);

	return reply;
}

// get the card id
std::string EDLCard::getCardID() {
	return "FAKE-ID-123";
}

// authenticate the pin, returns 0xFF on success or else the number of attempts left
int EDLCard::authPin(std::string pin) {
	byte insVerifyCmd[] = {0x00, 0x20, 0x00, 0x00, 0x04 };
	ByteVec cmd = MAKEVECTOR( insVerifyCmd);

	for(int i=0;i<pin.length();i++)
		cmd.push_back(pin[i]);

	try
	{
		ByteVec reply = execute(cmd);
		return 0xFF; // no error so pin is ok
	}
	catch(CardError &err)
	{
		if(err.SW1 == 0x63 && (err.SW2 == 0xC2 || err.SW2 == 0xC1 || err.SW2 == 0xC0 ))
			return err.SW2 - 0xC0; // error so pin is not ok
	}

	return 0; // don't know what happened but something is wrong
}