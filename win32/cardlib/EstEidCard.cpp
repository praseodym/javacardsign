/*!
	\file		EstEidCard.cpp
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )    
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-11-14 03:30:21 +0200 (R, 14 nov 2008) $
*/
// Revision $Revision: 140 $
#include "precompiled.h"
#include "EstEidCard.h"
#include "helperMacro.h"
#include <algorithm>

using std::string;

bool EstEidCard::isInReader(unsigned int idx) {
	string ATR = mManager.getATRHex(idx);
	string::size_type p =ATR.find("4573744549442076657220312e30"); //"EstEID ver1.0"
	return string::npos != p ;
	}

void EstEidCard::enterPin(PinType pinType,string pin,bool forceUnsecure) {
	byte cmdEntPin[] = {0x00,0x20,0x00}; // VERIFY
	ByteVec cmd(MAKEVECTOR(cmdEntPin));
	cmd.push_back(pinType);
	if (pin.length() < 4) {
		if (pin.length()!= 0 ||!mConnection->isSecure() ) 
			throw std::runtime_error("bad pin length");
	} else {
		cmd.push_back(LOBYTE(pin.length()));
		for(unsigned i=0;i<pin.length();i++) cmd.push_back(pin[i]);
	}
	try {
		if (forceUnsecure || !mConnection->isSecure()) 
			execute(cmd,true);//exec as a normal command
		else
			executePinEntry(cmd);
	} catch(AuthError &ae) {
		throw AuthError(ae); 
	} catch(CardError &e) {
		if (e.SW1 == 0x63) throw AuthError(e);
		if (e.SW1 == 0x69 && e.SW2 == 0x83) throw AuthError(e.SW1,e.SW2,true);
		throw e;
		}
	}

void EstEidCard::setSecEnv(byte env) {
	byte cmdSecEnv1[] = {0x00,0x22,0xF3};
	ByteVec cmd(MAKEVECTOR(cmdSecEnv1));
	cmd.push_back(env);
	execute(cmd,true);
}

void EstEidCard::prepareSign_internal(KeyType keyId,string pin) { 
	selectMF(true);
	selectDF(FILEID_APP,true);
	if (keyId == 0 )	enterPin(PIN_AUTH,pin);
	else				enterPin(PIN_SIGN,pin);
	}

ByteVec EstEidCard::calcSign_internal(AlgType type,KeyType keyId,ByteVec hash,bool withOID) {
	byte signCmdSig[] = {0x00,0x2A,0x9E,0x9A};
	byte signCmdAut[] = {0x00,0x88,0x00,0x00};
	byte hashHdMD5[] = {
		0x30,0x20,0x30,0x0C,0x06,0x08,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x05,0x05,0x00,
		0x04,0x10};
	byte hashHdSHA1[] = {
		0x30,0x21,0x30,0x09,0x06,0x05,0x2B,0x0E,0x03,0x02,0x1A,0x05,0x00,0x04,0x14 };

	ByteVec cmd,header;
	if (keyId == 0 )
		cmd = MAKEVECTOR(signCmdAut);
	else
		cmd = MAKEVECTOR(signCmdSig);

	if (withOID) {
		switch(type) {
			case MD5 : header = MAKEVECTOR(hashHdMD5);break;
			case SHA1: header = MAKEVECTOR(hashHdSHA1);break;
			default: throw std::runtime_error("cannot calculate SSL signature with OID");
			}
		cmd.push_back( (byte) (header.size() + hash.size()));
		cmd.insert(cmd.end(),header.begin(),header.end());
		}
	else 
		cmd.push_back((byte)hash.size());

	setSecEnv(1);

	cmd.insert(cmd.end(),hash.begin(),hash.end());
	ByteVec result;
	try {
		result = execute(cmd);
	} catch(CardError e) {
		if (e.SW1 == 0x69 && (e.SW2 == 0x82 || e.SW2 == 0x00 || e.SW2 == 0x85 )) 
			throw AuthError(e);
		throw e;
		}
	return result;
	}

ByteVec EstEidCard::RSADecrypt_internal(ByteVec cipher) {
	byte modEnv1[] = {0x00,0x22,0x41,0xA4,0x02,0x83,0x00};
	byte modEnv2[] = {0x00,0x22,0x41,0xB6,0x02,0x83,0x00};
	byte modEnv0[] = {0x00,0x22,0x41,0xB8,0x05,0x83,0x03,0x80}; 

	selectMF(true);
	selectDF(FILEID_APP,true);
	selectEF(FILEID_KEYPOINTER,true);
	ByteVec keyRec = readRecord(1);
	if (keyRec.size() != 0x15)
			throw CardDataError("key ptr len is not 0x15");
	ByteVec cmd(MAKEVECTOR(modEnv0));
	cmd.insert(cmd.end(),&keyRec[0x9],&keyRec[0xB]);

	setSecEnv(6);
	execute(MAKEVECTOR(modEnv1),true);
	execute(MAKEVECTOR(modEnv2),true);
	execute(cmd,true);

	byte decrpt[] = {0x00,0x2A,0x80,0x86,0x81,0x00};
	ByteVec decCmd(MAKEVECTOR(decrpt));
	decCmd.insert(decCmd.end(),cipher.begin(),cipher.end());

	ByteVec result;
	try {
		result = execute(decCmd,false);
	} catch(CardError e) {
/*		if (e.SW1 == 0x69 && e.SW2 == 0x88 ) {
			reverse(decCmd.begin() + 6, decCmd.end());
			result = execute(decCmd,false);
			return result;
			}*/
		if (e.SW1 == 0x69 && (e.SW2 == 0x82 || e.SW2 == 0x00 || e.SW2 == 0x88  || e.SW2 == 0x85  
			/*|| e.SW1 == 0x64 */|| e.SW1 == 0x6B ))
			throw AuthError(e);
		throw e;
		}
	return result;
	}

void EstEidCard::readPersonalData_internal(vector<string>& data,int recStart,int recEnd) {
	selectMF(true);
	selectDF(FILEID_APP,true);
	FCI fileInfo = selectEF(0x5044);
	
	if (fileInfo.recCount != 0x10 && fileInfo.recCount != 0x0A ) 
		throw CardDataError("personal data file does not contain 16 or 10 records");
	data.resize(std::min(recEnd,0x10) + 1 );
	for (int i=recStart; i <= recEnd; i++) {
		ByteVec record = readRecord(i);
		string& ret = data[i];
		for (ByteVec::iterator c = record.begin();c!=record.end();c++) 	
			ret+= *c ;
		}
	}

bool EstEidCard::validatePin_internal(PinType pinType,string pin, byte &retriesLeft,bool forceUnsecure) { 
	checkProtocol();
	selectMF(true);
	if (retriesLeft != 0xFA ) { //sorry, thats a bad hack around sloppy interface definition
		retriesLeft = 0;
		selectEF(FILEID_RETRYCT,true);
		ByteVec data = readRecord(pinType == PUK ? 3 : pinType );
		ByteVec tag = getTag(0x90,1,data);
		retriesLeft = tag[0];
		}
	selectDF(FILEID_APP,true);
	enterPin(pinType,pin);
	return true;
	}

bool EstEidCard::changePin_internal(
	PinType pinType,std::string newPin,std::string oldPin,bool useUnblockCmd ) {
	byte cmdChangeCmd[] = {0x00,0x24,0x00};
	
	if (useUnblockCmd) cmdChangeCmd[1]= 0x2C;

	size_t oldPinLen,newPinLen;

	if (newPin.length() < 4 || oldPin.length() < 4 ) {
		if (newPin.length()!= 2 || oldPin.length() != 2 ||
			!mConnection->isSecure() ) 
			throw std::runtime_error("bad pin length");
		oldPinLen = (oldPin[0] - '0') * 10 + oldPin[1] - '0';
		newPinLen = (newPin[0] - '0') * 10 + newPin[1]- '0';
		oldPin = string(oldPinLen,'0');
		newPin = string(newPinLen,'0');
	} else {
		oldPinLen = oldPin.length();
		newPinLen = newPin.length();
	}

	ByteVec catPins;
	catPins.resize(oldPinLen + newPinLen);
	copy(oldPin.begin(), oldPin.end(), catPins.begin());
	copy(newPin.begin(), newPin.end(), catPins.begin() + oldPin.length());

	ByteVec cmd(MAKEVECTOR(cmdChangeCmd));
	cmd.push_back(pinType);
	cmd.push_back(LOBYTE(catPins.size()));
	cmd.insert(cmd.end(),catPins.begin(),catPins.end());
	try {
		if (mConnection->isSecure()) 
			executePinChange(cmd,oldPinLen,newPinLen);
		else
			execute(cmd,true);
	} catch(AuthError &ae) {
		throw AuthError(ae);
	} catch(CardError &e) {
		if (e.SW1 == 0x63) 
			throw AuthError(e);
		else if (useUnblockCmd && e.SW1==0x6a && e.SW2 == 0x80 ) //unblocking, repeating old pin
			throw AuthError(e.SW1,e.SW2,true);
		else 
			throw e;
		}

	return true;
	}

void EstEidCard::reconnectWithT0() {
	if (mConnection->mOwnConnection) {
	uint prev = mConnection->mIndex;
	delete mConnection;
	connect(prev,true);
	}
	else {
		mConnection = mManager.reconnect(mConnection,true);
		}
	}

void EstEidCard::checkProtocol() {
//	return;
	try {
		selectMF(true);
	} catch(CardError &ce) {
		if (ce.SW1 != 0x6A || ce.SW2 != 0x87 ) throw ce;
		reconnectWithT0();
		}
}

//transacted, public methods
string EstEidCard::readCardID() {
	vector<string> temp;
	Transaction _m(mManager,mConnection);
	checkProtocol();
	readPersonalData_internal(temp,ID,ID);

	string ret = temp[ID];
	return ret;
	}

string EstEidCard::readCardName() {
	vector<string> temp;
	Transaction _m(mManager,mConnection);
	checkProtocol();
	readPersonalData_internal(temp,SURNAME,FIRSTNAME);

	string ret = temp[SURNAME] + " " + temp[FIRSTNAME] ;
	return ret;
	}

bool EstEidCard::readPersonalData(vector<string>& data,
		int firstRecord,int lastRecord) {
		Transaction _m(mManager,mConnection);
		checkProtocol();
		readPersonalData_internal(data,firstRecord,lastRecord);
	return true;
	}

bool EstEidCard::getKeyUsageCounters(dword &authKey,dword &signKey) {
	Transaction _m(mManager,mConnection);
	selectMF(true);
	selectDF(FILEID_APP,true);

	selectEF(FILEID_KEYPOINTER,true);
	ByteVec keyRec = readRecord(1);
	if (keyRec.size() != 0x15)
			throw CardDataError("key ptr len is not 0x15");
	byte UsedKey = 0;
	if (keyRec[0x9]== 0x12 && keyRec[0xA] == 0x00 ) UsedKey++;

	FCI fileInfo = selectEF(0x0013);
	if (fileInfo.recCount < 4)
			throw CardDataError("key info file 0x13 should have 4 records");

	ByteVec authData = readRecord(UsedKey + 3);
	ByteVec signData = readRecord(UsedKey + 1);
	ByteVec aTag = getTag(0x91,3,authData);
	ByteVec sTag = getTag(0x91,3,signData);

	authKey = 0xFFFFFF - ((aTag[0] << 16) + (aTag[1] << 8) + aTag[2]);
	signKey = 0xFFFFFF - ((sTag[0] << 16) + (sTag[1] << 8) + sTag[2]);

	return true;
	}

ByteVec EstEidCard::getAuthCert() {
	Transaction _m(mManager,mConnection);

	selectMF(true);
	selectDF(FILEID_APP,true);
	FCI fileInfo = selectEF(0xAACE);

	return readEF(fileInfo.fileLength );
	}

ByteVec EstEidCard::getSignCert() {
	Transaction _m(mManager,mConnection);

	selectMF(true);
	selectDF(FILEID_APP,true);
	FCI fileInfo = selectEF(0xDDCE);
	return readEF(fileInfo.fileLength );
	}

ByteVec EstEidCard::calcSSL(ByteVec hash) {
	Transaction _m(mManager,mConnection);

	return calcSign_internal(SSL,AUTH,hash,false);
	}

ByteVec EstEidCard::calcSSL(ByteVec hash,string pin) {
	Transaction _m(mManager,mConnection);

	prepareSign_internal(AUTH,pin);
	return calcSign_internal(SSL,AUTH,hash,false);
	}

ByteVec EstEidCard::calcSignSHA1(ByteVec hash,KeyType keyId,bool withOID) {
	Transaction _m(mManager,mConnection);

	return calcSign_internal(SHA1,keyId,hash,withOID);
	}

ByteVec EstEidCard::calcSignSHA1(ByteVec hash,KeyType keyId,string pin,bool withOID) {
	Transaction _m(mManager,mConnection);

	prepareSign_internal(keyId,pin);
	return calcSign_internal(SHA1,keyId,hash,withOID);
	}

ByteVec EstEidCard::calcSignMD5(ByteVec hash,KeyType keyId,bool withOID) {
	Transaction _m(mManager,mConnection);

	return calcSign_internal(MD5,keyId,hash,withOID);
	}

ByteVec EstEidCard::calcSignMD5(ByteVec hash,KeyType keyId,std::string pin,bool withOID) {
	Transaction _m(mManager,mConnection);

	prepareSign_internal(keyId,pin);
	return calcSign_internal(MD5,keyId,hash,withOID);
	}

ByteVec EstEidCard::RSADecrypt(ByteVec cipher) {
	Transaction _m(mManager,mConnection);

	checkProtocol();
	return RSADecrypt_internal(cipher);
	}

ByteVec EstEidCard::RSADecrypt(ByteVec cipher,string pin) {
	Transaction _m(mManager,mConnection);

	selectMF(true);
	selectDF(FILEID_APP,true);
	enterPin(PIN_AUTH,pin);
	return RSADecrypt_internal(cipher);
	}

bool EstEidCard::validateAuthPin(string pin, byte &retriesLeft ) {
	Transaction _m(mManager,mConnection);
	return validatePin_internal(PIN_AUTH,pin,retriesLeft);
	}

bool EstEidCard::validateSignPin(string pin, byte &retriesLeft ) {
	Transaction _m(mManager,mConnection);
	return validatePin_internal(PIN_SIGN,pin,retriesLeft);
}

bool EstEidCard::validatePuk(string pin, byte &retriesLeft ) {
	Transaction _m(mManager,mConnection);
	return validatePin_internal(PUK,pin,retriesLeft);
}

bool EstEidCard::changeAuthPin(std::string newPin,std::string oldPin, byte &retriesLeft ) {
	Transaction _m(mManager,mConnection);
	if (!mConnection->isSecure())
		validatePin_internal(PIN_AUTH,oldPin,retriesLeft);
	else {
		byte dummy;
		getRetryCounts_internal(dummy,retriesLeft,dummy);
		}
	return changePin_internal(PIN_AUTH,newPin,oldPin);
	}

bool EstEidCard::changeSignPin(std::string newPin,std::string oldPin, byte &retriesLeft ) {
	Transaction _m(mManager,mConnection);
	if (!mConnection->isSecure())
		validatePin_internal(PIN_SIGN,oldPin,retriesLeft);
	else {
		byte dummy;
		getRetryCounts_internal(dummy,dummy,retriesLeft);
		}
	return changePin_internal(PIN_SIGN,newPin,oldPin);
	}

bool EstEidCard::changePUK(std::string newPUK,std::string oldPUK, byte &retriesLeft ) {
	Transaction _m(mManager,mConnection);
	if (!mConnection->isSecure())
		validatePin_internal(PUK,oldPUK,retriesLeft);
	else {
		byte dummy;
		getRetryCounts_internal(retriesLeft,dummy,dummy);
		}
	return changePin_internal(PUK,newPUK,oldPUK);
	}

bool EstEidCard::unblockAuthPin(std::string newPin,std::string mPUK, byte &retriesLeft ) {
	Transaction _m(mManager,mConnection);
	if (!mConnection->isSecure())
		validatePin_internal(PUK,mPUK,retriesLeft);
	if (newPin.length() < 4) 
		throw std::runtime_error("secure unblock not implemented yet");
	for(char i='0'; i < '6'; i++) try { //ENSURE its blocked
			validatePin_internal(PIN_AUTH,string("0000") + i ,retriesLeft,true);
		} catch (...) {}
	return changePin_internal(PIN_AUTH,newPin,mPUK,true);
	}

bool EstEidCard::unblockSignPin(std::string newPin,std::string mPUK, byte &retriesLeft ) {
	Transaction _m(mManager,mConnection);
	if (!mConnection->isSecure())
		validatePin_internal(PUK,mPUK,retriesLeft);
	if (newPin.length() < 4) 
		throw std::runtime_error("secure unblock not implemented yet");
	for(char i='0'; i < '6'; i++) try { //ENSURE its blocked
			validatePin_internal(PIN_SIGN,string("0000") + i ,retriesLeft,true);
		} catch (...) {}
	return changePin_internal(PIN_SIGN,newPin,mPUK,true);
	}

bool EstEidCard::getRetryCounts(byte &puk,byte &pinAuth,byte &pinSign) {
	Transaction _m(mManager,mConnection);
	return getRetryCounts_internal(puk,pinAuth,pinSign);
	}

bool EstEidCard::getRetryCounts_internal(byte &puk,byte &pinAuth,byte &pinSign) {
	ByteVec data,tag;
	selectMF(true);
	selectEF(FILEID_RETRYCT,true);
	data = readRecord(3);
	tag = getTag(0x90,1,data);
	puk = tag[0];
	data = readRecord(PIN_AUTH);
	tag = getTag(0x90,1,data);
	pinAuth = tag[0];
	data = readRecord(PIN_SIGN);
	tag = getTag(0x90,1,data);
	pinSign = tag[0];
	return true;
	}

void EstEidCard::resetAuth() {
	try {
		Transaction _m(mManager,mConnection);
		selectMF(true);
		setSecEnv(0);
	} catch (...) {}
	}
