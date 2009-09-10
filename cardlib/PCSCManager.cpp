/*!
	\file		PCSCManager.cpp
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-11-16 19:12:33 +0200 (P, 16 nov 2008) $
*/
// Revision $Revision: 146 $
#ifndef WINVER				// Allow use of features specific to Windows XP or later.
#define WINVER 0x0501		// Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifndef _WIN32_WINDOWS		// Allow use of features specific to Windows 98 or later.
#define _WIN32_WINDOWS 0x0410 // Change this to the appropriate value to target Windows Me or later.
#endif

#ifndef _WIN32_IE			// Allow use of features specific to IE 6.0 or later.
#define _WIN32_IE 0x0600	// Change this to the appropriate value to target other versions of IE.
#endif

#define NOMINMAX 

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include "version.h"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include "stdafx.h"
#include "PCSCManager.h"
#include "SCError.h"

#ifdef WIN32
#define LIBNAME "winscard"
#define SUFFIX "A"
#else
#if defined(__APPLE__)
#define LIBNAME "PCSC.framework/PCSC"
#define SUFFIX ""
#else
#define LIBNAME "pcsclite"
#define SUFFIX ""
#endif
#endif

using std::string;

PCSCManager::PCSCManager(void): mLibrary(LIBNAME),mOwnContext(true) 
{
	construct();
	SCError::check((*pSCardEstablishContext)(SCARD_SCOPE_USER,
					NULL,
					NULL,
					&mSCardContext));
}

PCSCManager::PCSCManager(SCARDCONTEXT existingContext): mLibrary(LIBNAME),mOwnContext(false) 
{
	construct();
	mSCardContext=existingContext;
}

void PCSCManager::construct()
{
#ifdef WIN32
	pSCardAccessStartedEvent = ( HANDLE(SCAPI *)() )
		mLibrary.getProc("SCardAccessStartedEvent");
	pSCardReleaseStartedEvent = (void(SCAPI *)(HANDLE))mLibrary.getProc("SCardReleaseStartedEvent");
#endif
	pSCardEstablishContext = (LONG(SCAPI *)(DWORD,LPCVOID,LPCVOID,SCARDCONTEXT*))
		mLibrary.getProc("SCardEstablishContext");
	pSCardReleaseContext = (LONG(SCAPI *)(SCARDCONTEXT))
		mLibrary.getProc("SCardReleaseContext");
	pSCardGetStatusChange = (LONG(SCAPI *)(SCARDCONTEXT,DWORD,SCARD_READERSTATE*,DWORD))
		mLibrary.getProc("SCardGetStatusChange" SUFFIX);
	pSCardListReaders = (LONG(SCAPI *)(SCARDCONTEXT,CSTRTYPE,STRTYPE,LPDWORD))
		mLibrary.getProc("SCardListReaders"  SUFFIX);
	pSCardTransmit = (LONG(SCAPI *)(SCARDHANDLE,LPCSCARD_IO_REQUEST,LPCBYTE,DWORD,LPSCARD_IO_REQUEST,LPBYTE,LPDWORD))
		mLibrary.getProc("SCardTransmit");
#ifndef __APPLE__
	pSCardGetAttrib = (LONG(SCAPI *)(SCARDHANDLE,DWORD,LPBYTE,LPDWORD))
		mLibrary.getProc("SCardGetAttrib");
#endif
	pSCardConnect = (LONG(SCAPI *)(SCARDCONTEXT ,CSTRTYPE ,DWORD ,DWORD ,SCARDHANDLE *,LPDWORD ))
		mLibrary.getProc("SCardConnect"  SUFFIX);
	pSCardReconnect = (LONG(SCAPI *)(SCARDHANDLE , DWORD ,DWORD ,DWORD ,LPDWORD ))
		mLibrary.getProc("SCardReconnect");
	pSCardDisconnect = (LONG (SCAPI *)(SCARDHANDLE hCard,DWORD dwDisposition))
		mLibrary.getProc("SCardDisconnect");
	pSCardBeginTransaction = (LONG(SCAPI *)(SCARDHANDLE ))
		mLibrary.getProc("SCardBeginTransaction");
	pSCardEndTransaction=(LONG(SCAPI *)(SCARDHANDLE ,DWORD ))
		mLibrary.getProc("SCardEndTransaction");
#ifdef WIN32
	pSCardStatus = (LONG(SCAPI *)(SCARDHANDLE ,STRTYPE ,LPDWORD ,
		LPDWORD ,LPDWORD ,LPBYTE ,LPDWORD ))
		mLibrary.getProc("SCardStatus" SUFFIX);

	mSCStartedEvent = (*pSCardAccessStartedEvent)();
	if (!mSCStartedEvent)
		throw std::runtime_error("SCardAccessStartedEvent returns NULL");
	//the timeout here is NEEDED under Vista/Longhorn, do not remove it
	if (WAIT_OBJECT_0 != WaitForSingleObject(mSCStartedEvent,1000) ) {
		throw std::runtime_error("Smartcard subsystem not started");
		}
#endif
}

PCSCManager::~PCSCManager(void)
{
	if (mOwnContext)
		(*pSCardReleaseContext)(mSCardContext);
#ifdef WIN32
// this crashes with "ESP not being preserved", wrong calling convention apparently
//	(*pSCardReleaseStartedEvent)(mSCStartedEvent);
#endif
}

void PCSCManager::ensureReaders(uint idx)
{
	DWORD ccReaders;
	SCError::check((*pSCardListReaders)(mSCardContext,NULL,NULL,&ccReaders));
	if (ccReaders == 0) {
		mReaderStates.clear();
		return;
		}
	if (ccReaders != mReaders.size()) { //check whether we have listed already
		mReaderStates.clear();
		mReaders.resize(ccReaders);
		SCError::check((*pSCardListReaders)(mSCardContext,NULL,&mReaders[0],&ccReaders));
		char* p = &mReaders[0];
		while(p < &*(--mReaders.end()) ) {
			SCARD_READERSTATE s = {p,NULL,SCARD_STATE_UNAWARE,0,0,{'\0'}};
			mReaderStates.push_back(s);
			p+= string(p).length() + 1;
			}
		if (mReaderStates.size() ==  0 )
			throw SCError(SCARD_E_READER_UNAVAILABLE);
		}

	SCError::check((*pSCardGetStatusChange)
		(mSCardContext,0, &mReaderStates[0],DWORD(mReaderStates.size())));
	if (idx >= mReaderStates.size())
		throw std::range_error("ensureReaders: Index out of bounds");
}

uint PCSCManager::getReaderCount()
{
	try {
		ensureReaders(0);
	} catch(SCError &err) {
		if (err.error == long(SCARD_E_NO_READERS_AVAILABLE))
			throw SCError(SCARD_E_READER_UNAVAILABLE);
		else
			throw err;
		}
	return (uint) mReaderStates.size();
}

string PCSCManager::getReaderName(uint idx)
{
	ensureReaders(idx);
	return mReaderStates[idx].szReader;
}

#define SS(a) if ((theState & SCARD_STATE_##a ) == SCARD_STATE_##a) \
	stateStr += string(#a) + string("|")

string PCSCManager::getReaderState(uint idx)
{
	ensureReaders(idx);
	DWORD theState = mReaderStates[idx].dwEventState;
	string stateStr = "";
	SS(IGNORE);
	SS(UNKNOWN);
	SS(UNAVAILABLE);
	SS(EMPTY);
	SS(PRESENT);
	SS(ATRMATCH);
	SS(EXCLUSIVE);
	SS(INUSE);
	SS(MUTE);
#ifdef SCARD_STATE_UNPOWERED
	SS(UNPOWERED);
#endif
	if (stateStr.length() > 0 ) stateStr = stateStr.substr(0,stateStr.length()-1);
	return stateStr ;
}

string PCSCManager::getATRHex(uint idx)
{
	ensureReaders(idx);
	std::ostringstream buf;
	buf << "";
	for(uint i=0;i<mReaderStates[idx].cbAtr;i++)
		buf << std::setfill('0') << std::setw(2) <<std::hex <<
		(short) mReaderStates[idx].rgbAtr[i];
	string retval = buf.str();
	return retval;
}

PCSCConnection * PCSCManager::connect(uint idx,bool forceT0)
{
	ensureReaders(idx);
	return new PCSCConnection(*this,idx,forceT0);
}

PCSCConnection * PCSCManager::connect(SCARDHANDLE existingHandle) {
	DWORD proto = SCARD_PROTOCOL_T0;
#ifdef WIN32 //quick hack, pcsclite headers dont have that
	DWORD tmpProto,sz=sizeof(DWORD);
	if (!(*pSCardGetAttrib)(existingHandle,SCARD_ATTR_CURRENT_PROTOCOL_TYPE,
		(LPBYTE)&tmpProto,&sz)) 
		proto = tmpProto;
#endif
	return new PCSCConnection(*this,existingHandle,proto);
}

PCSCConnection * PCSCManager::reconnect(ConnectionBase *c,bool forceT0) {
	PCSCConnection *pc = (PCSCConnection *)c;
	SCError::check((*pSCardReconnect)(pc->hScard, 
		SCARD_SHARE_SHARED, (pc->mForceT0 ? 0 : SCARD_PROTOCOL_T1 ) | SCARD_PROTOCOL_T0,
		SCARD_RESET_CARD,&pc->proto));
	return pc;
	}

void PCSCManager::makeConnection(ConnectionBase *c,uint idx)
{
	PCSCConnection *pc = (PCSCConnection *)c;
	SCError::check((*pSCardConnect)(mSCardContext, (CSTRTYPE) mReaderStates[idx].szReader,
		SCARD_SHARE_SHARED,
		(pc->mForceT0 ? 0 : SCARD_PROTOCOL_T1 ) | SCARD_PROTOCOL_T0
		, & pc->hScard,& pc->proto));
}

void PCSCManager::deleteConnection(ConnectionBase *c)
{
	SCError::check((*pSCardDisconnect)((( PCSCConnection *)c)->hScard,SCARD_RESET_CARD));
}

void PCSCManager::beginTransaction(ConnectionBase *c)
{
	SCError::check((*pSCardBeginTransaction)( (( PCSCConnection *)c)->hScard));
}

void PCSCManager::endTransaction(ConnectionBase *c,bool forceReset)
{
	if (forceReset) { //workaround for reader driver bug
		BYTE _rdrBuf[1024];
		STRTYPE reader = (STRTYPE) _rdrBuf;
		DWORD rdrLen = sizeof(reader);
		DWORD state,proto,result,active;
		BYTE atr[1024];
		DWORD atrLen = sizeof(atr);
		result = (*pSCardStatus)((( PCSCConnection *)c)->hScard,reader,&rdrLen,&state,&proto,atr,&atrLen);
		if (result == SCARD_W_RESET_CARD) {
			result = (*pSCardReconnect)((( PCSCConnection *)c)->hScard,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, 
				SCARD_LEAVE_CARD,&active);
			(*pSCardStatus)((( PCSCConnection *)c)->hScard,reader,&rdrLen,&state,&proto,atr,&atrLen);
			}
		}
	/*SCError::check(*/
	(*pSCardEndTransaction)((( PCSCConnection *)c)->hScard,forceReset ? SCARD_RESET_CARD : SCARD_LEAVE_CARD)
		/*)*/;
}

void PCSCManager::execCommand(ConnectionBase *c,std::vector<BYTE> &cmd
		,std::vector<BYTE> &recv,
		uint &recvLen) {
	PCSCConnection *pc = (PCSCConnection *)c;
	const SCARD_IO_REQUEST _MT0 = {1,8};
	const SCARD_IO_REQUEST _MT1 = {2,8};

	DWORD ret = recvLen;
	SCError::check((*pSCardTransmit)(pc->hScard,
				pc->proto == SCARD_PROTOCOL_T0 ? &_MT0 : &_MT1 ,
				&cmd[0],(DWORD)cmd.size() ,
				NULL,
				&recv[0] , &ret));
	recvLen = (uint)(ret);
}

bool PCSCManager::isT1Protocol(ConnectionBase *c) {
	PCSCConnection *pc = (PCSCConnection *)c;
	return pc->proto == SCARD_PROTOCOL_T1 && !pc->mForceT0;
	}
