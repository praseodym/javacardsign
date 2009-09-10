/*!
	\file		EstEidCard.h
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )    
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-11-14 03:36:37 +0200 (R, 14 nov 2008) $
*/
// Revision $Revision: 141 $
#pragma once
#include "CardBase.h"

/// Estonian ID card class. Supplies most of the card functions
class EstEidCard:
	public CardBase
{
	friend class EstEidCardMaintainer;
protected:
	enum {
		FILEID_MASTER = 0x3F00,
		FILEID_APP	  =	0xEEEE,
		FILEID_RETRYCT =	0x0016,
		FILEID_KEYPOINTER  = 0x0033
	};
public:

	enum PinType {
		PUK = 0,
		PIN_AUTH = 1,
		PIN_SIGN = 2
		};
	enum KeyType { AUTH = 0,SIGN = 1 };
	enum AlgType {
		MD5,SHA1,SSL
		};
	enum RecordNames {
		SURNAME = 1,
		FIRSTNAME,
		MIDDLENAME,
		SEX,
		CITIZEN,
		BIRTHDATE,
		ID,
		DOCUMENTID,
		EXPIRY,
		BIRTHPLACE,
		ISSUEDATE,
		RESIDENCEPERMIT,
		COMMENT1,COMMENT2,COMMENT3,COMMENT4
		};
private:
	void prepareSign_internal(KeyType keyId,std::string pin);
	ByteVec calcSign_internal(AlgType type,KeyType keyId, ByteVec hash,bool withOID = true);
	ByteVec RSADecrypt_internal(ByteVec cipher);
	void readPersonalData_internal(vector<std::string>& data,
		int firstRecord,int lastRecord );
	void enterPin(PinType pinType,std::string pin,bool forceUnsecure = false);
	bool validatePin_internal(PinType pinType,std::string pin, byte &retriesLeft,
		bool forceUnsecure = false);
	bool changePin_internal(
		PinType pinType,std::string newPin,std::string oldPin,bool useUnblockCommand=false);
	void reconnectWithT0();
	void checkProtocol();
	bool getRetryCounts_internal(byte &puk,byte &pinAuth,byte &pinSign);

public:
	EstEidCard(ManagerInterface &ref) : CardBase(ref) {}
	EstEidCard(ManagerInterface &ref,unsigned int idx) : 
	  CardBase(ref,idx) {}
	EstEidCard(ManagerInterface &ref,ConnectionBase *conn)  :
	  CardBase(ref,conn) {}
	~EstEidCard() {}
	bool isInReader(unsigned int idx);

	/// Reads the card holder identification code from personal data file
	std::string readCardID();
	/// Reads the card holder name from personal data file
	std::string readCardName();
	/// Reads entire or parts of personal data file from firstRecord to LastRecord
	bool readPersonalData(std::vector<std::string>& data,
		int firstRecord=SURNAME,int lastRecord=EXPIRY);
	/// gets accumulated key usage counters from the card
	bool getKeyUsageCounters(dword &authKey,dword &signKey);
	/// gets PIN entry retry counts for all three PINs
	bool getRetryCounts(byte &puk,byte &pinAuth,byte &pinSign);
	/// retrieve Authentication certificate
	ByteVec getAuthCert();
	/// retrieve Signature certificate
	ByteVec getSignCert();
	/// calculate SSL signature for SHA1+MD5 hash. PIN needs to be entered before
	ByteVec calcSSL(ByteVec hash);
	/// calculate SSL signature with PIN supplied, supply empty pin if cardmanager supports pin entry
	ByteVec calcSSL(ByteVec hash,std::string pin);
	
	/// calculate signature over SHA1 hash, keyid =0 selects auhtentication key, other values signature key. withOID=false calculates without SHA1 signatures, used for VPN
	ByteVec calcSignSHA1(ByteVec hash,KeyType keyId,bool withOID = true);
	/// calculate SHA1 signature with pin
	ByteVec calcSignSHA1(ByteVec hash,KeyType keyId,std::string pin,bool withOID = true);

	/// calculate signature over MD5 hash, keyid =0 selects auhtentication key
	ByteVec calcSignMD5(ByteVec hash,KeyType keyId,bool withOID = true);
	/// calculate signature over MD5 hash, with pin
	ByteVec calcSignMD5(ByteVec hash,KeyType keyId,std::string pin,bool withOID = true);

	/// decrypt RSA bytes, from 1024 bit/128 byte input vector, using authentication key
	ByteVec RSADecrypt(ByteVec cipher);
	/// decrypt RSA with authentication key, with pin supplied
	ByteVec RSADecrypt(ByteVec cipher,std::string pin);

	/// enter and validate authentication PIN. AuthError will be thrown if invalid
	bool validateAuthPin(std::string pin,byte &retriesLeft );
	/// enter and validate signature PIN
	bool validateSignPin(std::string pin,byte &retriesLeft );
	/// enter and validate PUK code
	bool validatePuk(std::string puk, byte &retriesLeft );

	/// change authentication PIN. For secure pin entry, specify pin lengths in "04" format, i.e. two-byte decimal string
	bool changeAuthPin(std::string newPin,std::string oldPin, byte &retriesLeft );
	/// change signature PIN
	bool changeSignPin(std::string newPin,std::string oldPin, byte &retriesLeft );
	/// change PUK
	bool changePUK(std::string newPUK,std::string oldPUK, byte &retriesLeft );
	/// unblock signature PIN using PUK. if correct PUK is supplied, the PIN will be first blocked and then unblocked
	bool unblockAuthPin(std::string newPin,std::string PUK, byte &retriesLeft );
	/// unblock signature PIN
	bool unblockSignPin(std::string newPin,std::string PUK, byte &retriesLeft );

	/// set security environment for the card. This does not need to be called directly, normally
	void setSecEnv(byte env);
	/// reset authentication, so next crypto operations will require new pin entry
	void resetAuth();
};
