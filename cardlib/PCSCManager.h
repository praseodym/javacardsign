/*!
	\file		PCSCManager.h
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-30 18:16:34 +0200 (N, 30 okt 2008) $
*/
// Revision $Revision: 134 $
#pragma once
#include "ManagerInterface.h"
#include "DynamicLibrary.h"
#include <winscard.h>

#ifdef WIN32
#define SCAPI __stdcall
#define CSTRTYPE const CHAR *
#define STRTYPE CHAR *
#undef SCARD_READERSTATE
#define SCARD_READERSTATE SCARD_READERSTATEA
#else
#define SCAPI
#ifdef LPCTSTR
define CSTRTYPE LPCSTR
#else
#define CSTRTYPE LPSTR
#endif
#define STRTYPE LPSTR
#ifndef SCARD_E_NO_READERS_AVAILABLE
#define SCARD_E_NO_READERS_AVAILABLE SCARD_E_READER_UNAVAILABLE
#endif
#include <wintypes.h>
#endif

/// Holds connection parameters for PCSC card connection
struct PCSCConnection : public ConnectionBase {
	SCARDHANDLE hScard;
	DWORD proto;
	PCSCConnection(ManagerInterface &iface,unsigned int index,bool force) :
		ConnectionBase(iface,index,force) {}
	PCSCConnection(ManagerInterface &iface,SCARDHANDLE existing,DWORD mProto): 
		ConnectionBase(iface),hScard(existing),proto(mProto) {}
	~PCSCConnection() {
	}
};

/// WinSCard/PCSCLite wrapper
/** PCSCManager represents WinSCard subsystem on Windows or PCSCLite libary
  on platforms where it is available. It loads the libraries dynamically to avoid
 linked-in dependencies */
class PCSCManager : public ManagerInterface {
	DynamicLibrary mLibrary;
	bool mOwnContext;
#ifdef WIN32
	HANDLE mSCStartedEvent;
#endif
	SCARDCONTEXT mSCardContext;
	std::vector<char > mReaders;
	std::vector<SCARD_READERSTATE> mReaderStates;

#ifdef WIN32
	HANDLE (SCAPI *pSCardAccessStartedEvent)();
	void (SCAPI *pSCardReleaseStartedEvent)(HANDLE hStartedEventHandle);
#endif
	LONG (SCAPI *pSCardEstablishContext)(DWORD scope,LPCVOID res1,LPCVOID res2,SCARDCONTEXT *context);
	LONG (SCAPI *pSCardReleaseContext)(SCARDCONTEXT hContext);
	LONG (SCAPI *pSCardGetStatusChange)(SCARDCONTEXT hContext,DWORD dwTimeout,SCARD_READERSTATE *rgReaderStates,DWORD cReaders);
	LONG (SCAPI *pSCardListReaders)(SCARDCONTEXT hContext,CSTRTYPE mszGroups,STRTYPE mszReaders,LPDWORD pcchReaders);
	LONG (SCAPI *pSCardTransmit)(SCARDHANDLE hCard,LPCSCARD_IO_REQUEST pioSendPci,
		LPCBYTE pbSendBuffer,DWORD cbSendLength,
		LPSCARD_IO_REQUEST pioRecvPci,LPBYTE pbRecvBuffer,
		LPDWORD pcbRecvLength);
	LONG (SCAPI *pSCardGetAttrib)(SCARDHANDLE hCard,DWORD dwAttrId,LPBYTE pbAttr,LPDWORD pcbAttrLen);
	LONG (SCAPI *pSCardConnect)(SCARDCONTEXT hContext,CSTRTYPE szReader,DWORD dwShareMode,
		DWORD dwPreferredProtocols,LPSCARDHANDLE phCard,LPDWORD pdwActiveProtocol);
	LONG (SCAPI *pSCardReconnect)(SCARDHANDLE hCard, DWORD dwShareMode,DWORD dwPreferredProtocols,DWORD dwInitialization,
		LPDWORD pdwActiveProtocol);
	LONG (SCAPI *pSCardDisconnect)(SCARDHANDLE hCard,DWORD dwDisposition);
	LONG (SCAPI *pSCardBeginTransaction)(SCARDHANDLE hCard);
	LONG (SCAPI *pSCardEndTransaction)(	SCARDHANDLE hCard,DWORD dwDisposition);
	LONG (SCAPI *pSCardStatus)( SCARDHANDLE hCard,STRTYPE szReaderName,LPDWORD pcchReaderLen,
		LPDWORD pdwState,LPDWORD pdwProtocol,LPBYTE pbAtr,LPDWORD pcbAtrLen);

	void construct(void);
	void ensureReaders(uint idx);

	void makeConnection(ConnectionBase *c,uint idx);
	void deleteConnection(ConnectionBase *c);
	void beginTransaction(ConnectionBase *c);
	void endTransaction(ConnectionBase *c,bool forceReset = false);
	void execCommand(ConnectionBase *c,std::vector<BYTE> &cmd,std::vector<BYTE> &recv,
		unsigned int &recvLen);
	bool isT1Protocol(ConnectionBase *c);

public:
	PCSCManager(void);
	/// construct with application-supplied card context
	PCSCManager(SCARDCONTEXT existingContext);
	~PCSCManager(void);
	uint getReaderCount();
	std::string getReaderName(uint idx);
	std::string getReaderState(uint idx);
	std::string getATRHex(uint idx);
	PCSCConnection * connect(uint idx,bool forceT0);
	/// connect using an application-supplied connection handle
	PCSCConnection * connect(SCARDHANDLE existingHandle);
	PCSCConnection * reconnect(ConnectionBase *c,bool forceT0);
};
