/*!
	\file		CardBase.cpp
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )    
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-30 18:16:34 +0200 (N, 30 okt 2008) $
*/
// Revision $Revision: 134 $
#include "stdafx.h"
#include "CardBase.h"
#include <algorithm>
#include "helperMacro.h"

CardError::CardError(byte a,byte b):runtime_error("invalid condition on card")
	,SW1(a),SW2(b) {
	std::ostringstream buf;
	buf << "CardError:'" << runtime_error::what() << "'" << 
		" SW1:'0x" <<
		std::hex << std::setfill('0') <<
		std::setw(2) << ushort(a) << "'"
		" SW2:'0x" <<
		std::hex << std::setfill('0') <<
		std::setw(2) << ushort(b) << "'"
		;
	desc = buf.str();
}

CardBase::CardBase(ManagerInterface &ref) :
	mManager(ref),mConnection(NULL),mLogger(ref.mLogger) {
	}

CardBase::CardBase(ManagerInterface &ref,unsigned int idx) :
	mManager(ref),mLogger(ref.mLogger)
{
	connect(idx);
}

CardBase::CardBase(ManagerInterface &ref,ConnectionBase *conn):
	mManager(ref),mConnection(conn),mLogger(ref.mLogger) {}

void CardBase::connect(unsigned int idx,bool forceT0) {
	mConnection = mManager.connect(idx,forceT0);
	}

CardBase::~CardBase(void)
{
	if (mConnection) {
		delete mConnection;
		mConnection = NULL;
		}
}

#define tagFCP 0x62 //file control parameters
#define tagFMD 0x64 //file management data
#define tagFCI 0x6F //file control information

ByteVec CardBase::getTag(int identTag,int len,ByteVec &arr) {
	std::ostringstream oss;
	ByteVec::iterator iTag;
	iTag = find(arr.begin(),arr.end(),identTag);
	if (iTag == arr.end() ) {
		oss <<  "fci tag not found, tag " << identTag;
		throw CardDataError( oss.str() );
		}
	if (len && *(iTag+1) != len) {
		oss <<  "fci tag " << identTag << " invalid length, expecting " <<
			len << " got " << int(*(iTag+1));
		throw CardDataError(oss.str());
		}

	return ByteVec(iTag + 2,iTag + 2 + *(iTag + 1));
	}

CardBase::FCI CardBase::parseFCI(ByteVec fci) {
	ByteVec tag;

	FCI tmp;
	tmp.fileID = 0;
	if (fci.size() < 0x0B ||
		(fci[0] != tagFCP && fci[0] != tagFCI)	|| 
		fci.size()-2 != fci[1] )
		throw CardDataError("invalid fci record");

	fci = ByteVec( fci.begin()+ 2  ,fci.end());

	tag = getTag(0x83,2,fci);
	if (tag.size() != 2) 
		throw CardDataError("file name record invalid length, not two bytes");
	tmp.fileID = MAKEWORD(tag[1],tag[0]);	

	tag = getTag(0x82,0,fci);
	switch (tag[0] & 0x3F) {
		case 0x38: //DF
		case 0x01: //binary
			if (tag.size() != 1) 
				throw CardDataError("linear variable file descriptor not 1 bytes long");
			tag = getTag(0x85,2,fci);
			tmp.fileLength = MAKEWORD(tag[1],tag[0]);
			break;
		case 0x02:
		//linear variable
		case 0x04:
			if (tag.size() != 5) 
				throw CardDataError("linear variable file descriptor not 5 bytes long");
			tmp.recMaxLen	= MAKEWORD( tag[0x03], tag[0x02] );
			tmp.recCount	= tag[0x04];
			tmp.fileLength	= 0;
			break;

		default:
			throw CardDataError("invalid filelen record, unrecognized tag");
		}
	return tmp;
}

CardBase::FCI CardBase::selectMF(bool ignoreFCI)
{
	//byte cmdMF[]= {0x00,0xA4,0x00,ignoreFCI ? 0x08 : 0x00,0x00/*0x02,0x3F,0x00*/}; 
	byte cmdMF[]= {0x00,0xA4,0x00,0x00,0x02,0x41,0x01,0x00}; 
	ByteVec code;
	code = execute( MAKEVECTOR(cmdMF));
	if (ignoreFCI) return FCI();
	return parseFCI(code);;
}

int CardBase::selectDF(int fileID,bool ignoreFCI)
{
	//byte cmdSelectDF[] = {0x00,0xA4,0x01,ignoreFCI ? 0x08 : 0x04,0x02};
	byte cmdSelectDF[] = {0x00,0xA4,0x00,0x00, 0x02};
	ByteVec cmd(MAKEVECTOR(cmdSelectDF));
	cmd.push_back(HIBYTE(fileID));
	cmd.push_back(LOBYTE(fileID));
	cmd.push_back(0);

	ByteVec fcp =  execute(cmd);
	if (ignoreFCI) return 0;
	FCI blah = parseFCI(fcp);
	return 0;
}

CardBase::FCI CardBase::selectEF(int fileID,bool ignoreFCI)
{
	//byte cmdSelectEF[] = {0x00,0xA4,0x02,ignoreFCI ? 0x08 : 0x04,0x02 };
	// 0xA4 == INS_SELECT
	byte cmdSelectEF[] = {0x00,0xA4,0x00,0x00, 0x02};
	ByteVec cmd(MAKEVECTOR(cmdSelectEF));
	cmd.push_back(HIBYTE(fileID));
	cmd.push_back(LOBYTE(fileID));
	cmd.push_back(0);
	ByteVec fci = execute(cmd);

	if (ignoreFCI) 
		return FCI();
	return parseFCI(fci);
}

#define PACKETSIZE 254
//#define PACKETSIZE 0x80

ByteVec CardBase::readEF(unsigned int  fileLen) 
{
	byte cmdReadEF[] = {0x00,0xB0,0x00,0x00,0x00};
	ByteVec cmd(MAKEVECTOR(cmdReadEF));

	ByteVec read(0);
	dword i=0;
	bool eof = false;
	
	do {
		byte bytes = LOBYTE( i + PACKETSIZE > fileLen ? fileLen - i : PACKETSIZE );
		
		cmd[2] = HIBYTE(i); //offsethi
		cmd[3] = LOBYTE(i); //offsetlo
		cmd[4] = bytes; //count
		//cmd[4] = PACKETSIZE;

		ByteVec ret;
		try {
			ret = execute(cmd,true);
		}
		catch(EndOfFileError & err) {
			ret = err.reply;
			eof = true;
		}
		
		
		if ( bytes != ret.size() && !eof ) 
			throw CardDataError("less bytes read from binary file than specified");

		read.insert(read.end(), ret.begin(),ret.end());
		i += PACKETSIZE ;
	} while (i < (fileLen - 1) && !eof);
	return read;
}

ByteVec CardBase::readRecord(int numrec) 
{
	byte cmdReadREC[] = {0x00,0xB2,0x00,0x04,0x00}; 

	cmdReadREC[2] = LOBYTE(numrec);
	return execute(MAKEVECTOR(cmdReadREC));
}

void CardBase::executePinEntry(ByteVec cmd) {
	mManager.execPinEntryCommand(mConnection,cmd);
	}

void CardBase::executePinChange(ByteVec cmd, size_t oldPinLen,size_t newPinLen) {
	mManager.execPinChangeCommand(mConnection,cmd,oldPinLen,newPinLen);
	}

void CardBase::setLogging(std::ostream *logStream) {
	mLogger = logStream;
	}

ByteVec CardBase::execute(ByteVec cmd,bool noreply)
{
	ByteVec RecvBuffer(1024);
	uint realLen = (uint) RecvBuffer.size() ;

	if (mManager.isT1Protocol(mConnection) && !noreply) {
		cmd.push_back(realLen);
		}

	if (mLogger != 0 && mLogger->good()) {
		*mLogger << "-> " ;
		if (mManager.isT1Protocol(mConnection)) *mLogger << "(T1)";
		else *mLogger << "(T0)";
		for(ByteVec::iterator it=cmd.begin();it < cmd.end(); it++ ) 
			*mLogger << std::hex << std::setfill('0') << std::setw(2) <<  (int) *it << " ";
		*mLogger << std::endl << std::endl;
		}

	mManager.execCommand(mConnection,cmd,RecvBuffer,realLen);
	
	if (realLen < 2) throw std::runtime_error("zero-length input from cardmanager");
	byte SW1 = RecvBuffer[ realLen - 2 ];
	byte SW2 = RecvBuffer[ realLen - 1 ];

	if (SW1 == 0x67 ) { //fallback, this should never occur in production
		cmd.pop_back();
		realLen = (dword) RecvBuffer.size();
		mManager.execCommand(mConnection,cmd,RecvBuffer,realLen);
		if (realLen < 2) throw std::runtime_error("zero-length input from cardmanager");
		SW1 = RecvBuffer[ realLen - 2 ];
		SW2 = RecvBuffer[ realLen - 1 ];
		}

	RecvBuffer.resize(realLen - 2);

	if (mLogger != 0 && mLogger->good()) {
		*mLogger << "<- ";
		*mLogger << "SW1=" << std::hex << std::setfill('0') << std::setw(2) <<  (int) SW1 << " ";
		*mLogger << "SW2=" << std::hex << std::setfill('0') << std::setw(2) <<  (int) SW2 << " ";
		for(ByteVec::iterator it=RecvBuffer.begin();it < RecvBuffer.end(); it++ ) 
			*mLogger << std::hex << std::setfill('0') << std::setw(2) <<  (int) *it << " ";
		*mLogger << std::endl << std::endl;
		}

	if (SW1 == 0x61) {
		byte cmdRead[]= {0x00,0xC0,0x00,0x00,0x00}; 
		cmdRead[4] = SW2;
		return execute(MAKEVECTOR(cmdRead));
		}

	if(SW1 == 0x62 && SW2 == 0x82)
		throw EndOfFileError(SW1, SW2, RecvBuffer);

	if (SW1 != 0x90) 
		throw CardError(SW1,SW2);

	return RecvBuffer;
}


void CardBase::endTransaction() {
	mManager.endTransaction(mConnection,true);
	}
