/*!
	\file		PCSCManager.h
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-13 00:04:13 +0300 (E, 13 okt 2008) $
*/
// Revision $Revision: 129 $
#pragma once
#include "ManagerInterface.h"

struct SmartCardManagerPriv;
struct SmartCardConnectionPriv;

struct SmartCardConnection : public ConnectionBase {
	SmartCardConnectionPriv *d;
	SmartCardConnection(int manager,ManagerInterface &iface,unsigned int index,
		bool force,ManagerInterface &orig);
	~SmartCardConnection();
};

/// Unified class for smarcard managers
/** SmartCardManager combines all system smartcard managers into one view
 Currently included are PCSCManager and CTAPIManager.
 */
class SmartCardManager : public ManagerInterface {
	SmartCardManagerPriv *d;

	void makeConnection(ConnectionBase *c,uint idx);
	void deleteConnection(ConnectionBase *c);
	void beginTransaction(ConnectionBase *c);
	void endTransaction(ConnectionBase *c,bool forceReset = false);
	void execCommand(ConnectionBase *c,std::vector<byte> &cmd,std::vector<byte> &recv,
		unsigned int &recvLen);
	bool isT1Protocol(ConnectionBase *c);

public:
	SmartCardManager(void);
	~SmartCardManager(void);

	uint getReaderCount();
	std::string getReaderName(uint idx);
	std::string getReaderState(uint idx);
	std::string getATRHex(uint idx);
	SmartCardConnection * connect(uint idx,bool forceT0);
	SmartCardConnection * reconnect(ConnectionBase *c,bool forceT0);
};
