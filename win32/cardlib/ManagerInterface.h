/*!
	\file		ManagerInterface.h
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )    
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-30 18:16:34 +0200 (N, 30 okt 2008) $
*/
// Revision $Revision: 134 $
#pragma once

typedef unsigned int uint;
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned long dword;
typedef unsigned short ushort;
/// shorthand for std::vector<unsigned char>, used everywhere
typedef	std::vector<byte> ByteVec;

struct ConnectionBase;

/// Abstraction of system smarcard managers
/** ManagerInterface is abstraction of system smartcard managers.
 Concrete managers are PCSCManager and CTAPIManager. Example additional 
 derivations might be direct communications driver or even serial/USB port */
class ManagerInterface
{
private: //disable object copying
	ManagerInterface(const ManagerInterface &);
	ManagerInterface& operator=(const ManagerInterface &);

public:
	ManagerInterface(void): mLogger(NULL) {}
	virtual ~ManagerInterface(void) {}
	/// number of installed readers
	virtual uint getReaderCount() = 0;
	/// name of the reader at index
	virtual std::string getReaderName(uint index)  = 0;
	/// string form of reader status at index, EMPTY, POWERED etc
	virtual std::string getReaderState(uint index) = 0;
	/// hex representation of card ATR in reader at index, empty string if no card is present
	virtual std::string getATRHex(uint index) = 0;
	/// connects instance of card to reader at index, forceT0 is used for cards that cant speak T1
	virtual ConnectionBase * connect(uint index,bool forceT0=false) = 0;
	/// reconnect using a different protocol
	virtual ConnectionBase * reconnect(ConnectionBase *c,bool forceT0=false) {return c;}
	/// use given stream as APDU log
	inline void setLogging(std::ostream *logStream) {mLogger = logStream;}
protected:
	std::ostream  *mLogger;
	friend struct ConnectionBase;
	friend struct Transaction;
	friend class  CardBase;
	friend class SmartCardManager;
	friend struct SmartCardConnection;
	virtual void makeConnection(ConnectionBase *c,uint idx) = 0;
	virtual void deleteConnection(ConnectionBase *c) = 0;
	virtual void beginTransaction(ConnectionBase *c) = 0;
	virtual void endTransaction(ConnectionBase *c,bool forceReset = false) = 0;

	virtual void execCommand(ConnectionBase *c,std::vector<byte> &cmd,std::vector<byte> &recv,
		unsigned int &recvLen) = 0;
	virtual void execPinEntryCommand(ConnectionBase *c,std::vector<byte> &cmd) {
		throw std::runtime_error("This manager does not support PIN entry commands");
		}
	virtual void execPinChangeCommand(ConnectionBase *c,std::vector<byte> &cmd
		,size_t oldPinLen,size_t newPinLen) { 
		throw std::runtime_error("This manager does not support PIN change commands");
		}
	/// tell if given connection is using T1 (true) or T0
	virtual bool isT1Protocol(ConnectionBase *c) = 0;
};

/// Represents connection to smart card reader
/** ConnectionBase represents a connection of a smart card instance to reader, 
    and holds the connection parameters. 
    Concrete derivations are PCSCConnection and CTAPIConnection */
struct ConnectionBase {
	/// reference to Manager
	ManagerInterface &mManager;
	/// reader index
	uint mIndex;
	/// force T0 protocol for connection
	bool mForceT0;
	/// if false, we are using application-supplied connection handle
	bool mOwnConnection;

	/// tells if the manager has a secure PIN input method, true for CTAPI
	virtual bool isSecure() {return false;}
	ConnectionBase(ManagerInterface &manager) : 
		mManager(manager),mIndex(-1),mForceT0(false),mOwnConnection(false) {}
	ConnectionBase(ManagerInterface &manager,unsigned int index,bool f) 
		: mManager(manager),mIndex(index),mForceT0(f),mOwnConnection(true) {
		mManager.makeConnection(this,index);
		}
	virtual ~ConnectionBase() {
		if (mOwnConnection)
			mManager.deleteConnection(this);
		}
};

/// Wraps a beginTransaction/endTransaction pair
/** Transaction wraps a beginTransaction/endTransaction pair, so functions can be performed 
 on cards without interruptions. It needs to be instanced from a given smart card function
 that needs to be performed as an atomic unit */
struct Transaction {
	ManagerInterface& mManager;
	ConnectionBase *mConnection;
	Transaction(ManagerInterface& manager,ConnectionBase *connection): mManager(manager),mConnection(connection) {
		mManager.beginTransaction(mConnection);
		}
	~Transaction() {
		mManager.endTransaction(mConnection);
		}
	};
