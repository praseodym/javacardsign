/*!
	\file		PCSCManager.cpp
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-30 18:16:34 +0200 (N, 30 okt 2008) $
*/
// Revision $Revision: 134 $
#include "precompiled.h"
#include "SmartCardManager.h"
#include "PCSCManager.h"
#include "CTAPIManager.h"

enum mgrType {
	MANAGER_PCSC,
	MANAGER_CTAPI
	};

struct SmartCardConnectionPriv {
	int m_manager;
	PCSCConnection *pcscConn;
	CTAPIConnection *ctConn;
	ManagerInterface &m_managerOriginal;
	SmartCardConnectionPriv(int manager,ManagerInterface &iface,unsigned int index,bool force,
		ManagerInterface &origMgr) :
		m_manager(manager),pcscConn(NULL),ctConn(NULL)
			,m_managerOriginal(origMgr) {
		if (m_manager == MANAGER_PCSC) pcscConn = new PCSCConnection(m_managerOriginal,index,force);
		if (m_manager == MANAGER_CTAPI) ctConn = new CTAPIConnection(m_managerOriginal,index,force);
		}
	~SmartCardConnectionPriv() {
		if (m_manager == MANAGER_PCSC) delete pcscConn;
		if (m_manager == MANAGER_CTAPI) delete ctConn;
		}
	ConnectionBase * getConnection() {
		if (m_manager == MANAGER_PCSC) return pcscConn;
		if (m_manager == MANAGER_CTAPI) return ctConn;
		throw std::runtime_error("Invalid smartcardconnection");
		}
};

SmartCardConnection::SmartCardConnection(int manager,ManagerInterface &iface,unsigned int index,bool force
										 ,ManagerInterface &orig) 
	:ConnectionBase(iface) {
	d = new SmartCardConnectionPriv(manager,iface,index,force,orig);
	}

SmartCardConnection::~SmartCardConnection() {
	d->m_managerOriginal.deleteConnection(this);
	delete d;
	}

struct SmartCardManagerPriv {
	PCSCManager pcscMgr;
	CTAPIManager ctMgr;
	ManagerInterface *connIf;
	uint pcscCount;
	uint ctCount;
	SmartCardManagerPriv() : connIf(&pcscMgr) {
		pcscCount = pcscMgr.getReaderCount();
		ctCount = ctMgr.getReaderCount();
		}
	ManagerInterface & getIndex(uint &i) {
		if (i < pcscCount ) 
			return pcscMgr;
		i-= pcscCount;
		return ctMgr;
		}
	};

SmartCardManager::SmartCardManager(void) {
	d = new SmartCardManagerPriv();
}

SmartCardManager::~SmartCardManager(void) {
	delete d;
}

void SmartCardManager::makeConnection(ConnectionBase *c,uint idx) {
//	SmartCardConnection *pc = (SmartCardConnection *)c;
	d->connIf->makeConnection( c , idx);
	}

void SmartCardManager::deleteConnection(ConnectionBase *c) {
	SmartCardConnection *pc = (SmartCardConnection *)c;
	pc->mManager.deleteConnection(pc->d->getConnection());
	pc->d->getConnection()->mOwnConnection = false; // ensure no duplicate delete
	}

void SmartCardManager::beginTransaction(ConnectionBase *c) {
	SmartCardConnection *pc = (SmartCardConnection *)c;
	pc->mManager.beginTransaction(pc->d->getConnection());
	}

void SmartCardManager::endTransaction(ConnectionBase *c,bool forceReset) {
	SmartCardConnection *pc = (SmartCardConnection *)c;
	pc->mManager.endTransaction(pc->d->getConnection());
	}

void SmartCardManager::execCommand(ConnectionBase *c,std::vector<BYTE> &cmd,std::vector<BYTE> &recv,
								   unsigned int &recvLen) {
	SmartCardConnection *pc = (SmartCardConnection *)c;
	pc->mManager.execCommand(pc->d->getConnection(),cmd,
		recv,recvLen);
}

bool SmartCardManager::isT1Protocol(ConnectionBase *c) {
	SmartCardConnection *pc = (SmartCardConnection *)c;
	return pc->mManager.isT1Protocol(pc->d->getConnection());
	}

uint SmartCardManager::getReaderCount() {
	return d->ctMgr.getReaderCount() + d->pcscMgr.getReaderCount();
	}

std::string SmartCardManager::getReaderName(uint idx) {
	uint t_idx = idx;
	return d->getIndex(t_idx).getReaderName(t_idx);
	}

std::string SmartCardManager::getReaderState(uint idx) {
	uint t_idx = idx;
	return d->getIndex(t_idx).getReaderState(t_idx);
	}

std::string SmartCardManager::getATRHex(uint idx) {
	uint t_idx = idx;
	return d->getIndex(t_idx).getATRHex(t_idx);
	}

SmartCardConnection * SmartCardManager::connect(uint idx,bool forceT0) {
	uint t_idx = idx;
	ManagerInterface &mgr = d->getIndex(t_idx);
	d->connIf = &mgr; //hack, passing down to makeConnection
	SmartCardConnection *retConn;
	if (&mgr == &d->pcscMgr)
		retConn = new SmartCardConnection(MANAGER_PCSC,mgr,t_idx,forceT0,*this);
	if (&mgr == &d->ctMgr)
		retConn = new SmartCardConnection(MANAGER_CTAPI,mgr,t_idx,forceT0,*this);
	return retConn;
	}

SmartCardConnection * SmartCardManager::reconnect(ConnectionBase *c,bool forceT0) {
	throw std::runtime_error("err, unimplemented");
	return 0;
	}
