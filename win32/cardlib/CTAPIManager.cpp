/*!
	\file		CTAPIManager.cpp
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-30 18:16:34 +0200 (N, 30 okt 2008) $
*/
// Revision $Revision: 134 $
#include "precompiled.h"
#include "CTAPIManager.h"
#include "helperMacro.h"
#include "CardBase.h" //for exceptions
using std::string;
using std::runtime_error;

#define CTERR_OK		0		//Function call was successful
#define CTERR_INVALID	-1		//Invalid parameter or value
#define CTERR_CT		-8		//CT error 1)
#define CTERR_TRANS		-10		//Non-eliminable transmission error2)
#define CTERR_MEMORY	-11		//Memory assign-ment error in HTSI3)
#define CTERR_HOST		-127	//Abort of function by host/OS
#define CTERR_HTSI		-128	//HTSI error

#define CTSAD_HOST		0x02
#define CTSAD_REM_HOST	0x05

#define CTDAD_ICC1		0x00
#define CTDAD_CT		0x01	//cardTerminal
#define CTDAD_ICC2		0x02
#define CTDAD_ICC3		0x03

#define INS_RESETCT		0x11
#define INS_REQICC		0x12
#define INS_GETSTATUS	0x13
#define INS_EJECTICC	0x15
#define INS_INPUT		0x16
#define INS_OUTPUT		0x17
#define INS_VERIFY		0x18
#define INS_MODIFY		0x19

const char* libNames[] =
	//omnikey , SCM ??
	{"openctapi","ctdeutin.dll","ctpcsc32.dll"};
#define MAXPORTS 6
const unsigned char ports[LENOF(libNames)][MAXPORTS]={
	{0,1,2,3,4,5},{0,30,35,60,70,75},{0,0,0,0,0,0}};

class CTAPIError : public CardError {
public:
	CTAPIError(const char *d,byte res,size_t len,byte SW1,byte SW2) :
			CardError(SW1,SW2) {
		std::ostringstream buf;
		buf << "CTAPI '" << d <<
			"' res:" << ushort(res) << " len:" << len << " ";
		desc = buf.str() + desc;
		}
	};

void dump(std::ostream *sout,string prefix,ByteVec &cmd) {
	if (!sout) return;
	*sout << prefix;
	for(ByteVec::iterator it=cmd.begin();it < cmd.end(); it++ ) 
		*sout << std::hex << std::setfill('0') << std::setw(2) <<  (int) *it << " ";
	*sout << std::endl << std::endl;
	}

void CTDriver::CTPort::performCmd(byte target,ByteVec cmd,ByteVec &resp,
				std::ostream *mLogger,bool consumeStatus ) {
	byte response[512];
	ushort lenr = sizeof(response);
	byte sad = CTSAD_HOST;
	dump(mLogger,string("CTAPI->cmd ") + (target == CTDAD_CT ? "CT " : "ICC " ),cmd);
	byte res = dri->pCTData(mCtn,&target,&sad,
		ushort(cmd.size()),&cmd[0],&lenr,response);
	if (res!=CTERR_OK || lenr < 2)
		throw CTAPIError("performCmd",res,lenr,0,0);
	resp.resize(0);
	resp.insert(resp.end(),response,response+lenr);
	dump(mLogger,"CTAPI<-resp ",resp);
	if (consumeStatus) {
		byte SW1 = resp[ lenr - 2 ];
		byte SW2 = resp[ lenr - 1 ];
		if (SW1 != 0x90) {
			if (sad == CTDAD_CT) {
				if (SW1==0x64 && ( SW2 == 0x00 || SW2 == 0x01 || SW2 == 0x02) ) {
					throw AuthError(SW1,SW2);
					}
				}
			throw CardError(SW1,SW2);
			}
		resp.resize(lenr - 2);
		}
}

void CTDriver::CTPort::performCmd(byte target,ByteVec cmd,std::ostream *mLogger) {
	ByteVec resp;
	performCmd(target,cmd,resp,mLogger);
	}

void CTDriver::CTPort::resetCT(byte unit,std::ostream *mLogger) {
	byte resetCmd[] = {0x20,INS_RESETCT,unit,0x00};
	//if (unit != 0) resetCmd[3] = 0x01;//return ATR
	performCmd(CTDAD_CT,MAKEVECTOR(resetCmd),mLogger);
	}

bool CTDriver::CTPort::init(bool nothrow) {
	mCtn = dri->nextCtn++;
	byte res = dri->pCTInit(mCtn, portNum);
	if (res!=CTERR_OK && !nothrow)
		throw CTAPIError("init",res,0,0,0);
	isConnected = true;
	return true;
	}

void CTDriver::CTPort::close() {
	dri->pCTClose(mCtn);
/*	if (res!=CTERR_OK) //thou shalt not throw in desctructors, alrite ?
		throw runtime_error("ctapi3");*/
	isConnected = false;
	}

CTDriver::CTDriver(const char *libName,std::vector<ushort> probePorts) :
		lib(libName),nextCtn(100)  {
	pCTInit = (char (CTAPI *)(ushort ctn,ushort pn)) lib.getProc("CT_init");
	pCTClose= (char (CTAPI *)(ushort ctn)) lib.getProc("CT_close");
	pCTData = (char (CTAPI *)(ushort ctn,byte * dad,byte * sad,ushort lenc,
					byte * command,ushort * lenr,byte * response))
					lib.getProc("CT_data");
	ByteVec lastResp;
	for(vector<ushort>::iterator it = probePorts.begin();
			it != probePorts.end() ; it++)
		try {
			byte res = (*pCTInit)(++nextCtn,*it);
			if (res == CTERR_OK ) {
				byte cmd[] = {0x20,INS_GETSTATUS,0x00,0x46,0x00}; //get reader 
				ByteVec resp;
				CTPort port(this,*it);
				port.init(true);
				port.performCmd(CTDAD_CT,MAKEVECTOR(cmd),resp,NULL);
				port.close();
				pCTClose(nextCtn);
				if (lastResp!= resp ) { //only add this port if different from previous
					mPorts.push_back(CTPort(this,*it));
					lastResp = resp;
					}
				}
		} catch (std::runtime_error& )	{}
	}

CTAPIManager::CTAPIManager(void)
{
	for(size_t i=0;i < LENOF(libNames);i++) {
		try {
			CTDriver *dri = new CTDriver(libNames[i],
				std::vector<ushort>(ports[i],ports[i] + MAXPORTS));
			mDrivers.push_back(dri);
			for(size_t j=0;j < dri->mPorts.size(); j++) {
				std::vector<cPort>::iterator port = dri->mPorts.begin() + j;
				mPorts.push_back(&*port);
				}
		} catch (std::runtime_error& )	{}
	}
}

void CTAPIManager::getDefaultLibAndPort(std::string &lib,uint &port) {
	if (!mDrivers.size()) return;
	for(size_t i = 0; i < mDrivers.size() ; i++ ) {
		lib = mDrivers[i]->lib.getName();
		if (!mDrivers[i]->mPorts.size()) continue;
		port = mDrivers[i]->mPorts.begin()->portNum;
		}
	}

CTAPIManager::~CTAPIManager(void)
{
	while(!mDrivers.empty()) {
		CTDriver *dri = *(--mDrivers.end());
		delete dri;
		mDrivers.pop_back();
		}
}
uint CTAPIManager::getReaderCount()
{
	return uint(mPorts.size());
}

struct initclose { //wrap init/close pairs to be safe
	cPort *mdri;
	bool wasConnected;
	initclose(cPort *dri) :mdri(dri),wasConnected(dri->isConnected) {
		if (!wasConnected) mdri->init();
		}
	~initclose() {
		if (!wasConnected) mdri->close();
		}
	};

string CTAPIManager::getReaderName(uint index)
{
	string retval;
	cPort *dri = mPorts[index];
	byte cmd[] = {0x20,INS_GETSTATUS,0x00,0x46,0x00};
	initclose _i(dri);

	ByteVec resp;
	dri->performCmd(CTDAD_CT,MAKEVECTOR(cmd),resp,mLogger);
	if (resp[0] != 0x46) {
		if (resp.size() != 2) { //openCT
			throw CTAPIError("getReaderName",0,resp.size(),resp[0],resp[1]);
			}
		return "opensc?";
		}
	resp.erase(resp.begin(),resp.begin()+2);
	retval.resize(resp.size());
	copy(resp.begin(),resp.end(),retval.begin());
	return retval;
}

string CTAPIManager::getReaderState(uint index)
{
	string retval;
	cPort *dri = mPorts[index];
//	byte cmd[] = {0x20,INS_GETSTATUS,0x00,0x80,0x00}; //GET STATUS, CT, all ICC status
//	byte cmd[] = {0x20,INS_GETSTATUS,0x00,0x81,0x00}; //GET STATUS, CT, functional spec
	byte cmd[] = {0x20,INS_GETSTATUS,0x01,0x80,0x00}; //GET STATUS, ICC0, ICC0 status

	initclose _i(dri);

	ByteVec resp;
	dri->performCmd(CTDAD_CT,MAKEVECTOR(cmd),resp,mLogger);
	if(resp.size() != 3) {
		if (resp.size() == 2) //workaround for openct
			resp.insert(resp.begin(),0x80);
		else
			throw CTAPIError("getReaderState0",0,resp.size(),0,0);
		}
	if (resp[0] != 0x80)
		throw CTAPIError("getReaderState1",0,resp.size(),resp[0],0);
	byte statusICC0 = resp[2];
	if (statusICC0 & 0x01)
		retval+= "PRESENT|";
	else
		retval+= "EMPTY|";
	if ((statusICC0 & 0x6) == 0x2)
		retval+= "UNPOWERED|";
	if ((statusICC0 & 0x6) == 0x4)
		retval+= "INUSE|";
	if (retval.length() > 0 )
		retval = retval.substr(0,retval.length()-1);
	return retval;
}

//"icc status data object" . ct-bcs"
string CTAPIManager::getATRHex(uint index)
{
	string retval;
	cPort *dri = mPorts[index];

	byte cmd[] = {0x20,INS_GETSTATUS,0x00,0x80,0x00};

	initclose _i(dri);

	ByteVec resp;
	dri->performCmd(CTDAD_CT,MAKEVECTOR(cmd),resp,mLogger);
	if (resp[2] == 0) {
		return "";
		}

	byte cmdReq[] = {0x20,INS_REQICC,0x01,0x01,0x00}; // req ICC1, return ATR
	dri->performCmd(CTDAD_CT,MAKEVECTOR(cmdReq),resp,mLogger);

	std::ostringstream buf;
	buf << "";
	for(uint i=0;i < resp.size();i++)
		buf << std::setfill('0') << std::setw(2) <<std::hex <<
		(short) resp[i];
	retval = buf.str();

	return retval;
}
CTAPIConnection * CTAPIManager::connect(uint index,bool forceT0)
{
	return new CTAPIConnection(*this,index,forceT0);
}

void CTAPIManager::makeConnection(ConnectionBase *c,uint index)
{
	CTAPIConnection *conn = (CTAPIConnection *) c;
	cPort *dri = mPorts[index];
	conn->wasConnected = dri->isConnected;
	conn->dri = dri;
	if (!conn->wasConnected)
		dri->init();
	dri->resetCT(1,mLogger);
}

void CTAPIManager::deleteConnection(ConnectionBase *c)
{
	CTAPIConnection *conn = (CTAPIConnection *) c;
	if (!conn->wasConnected)
		conn->dri->close();
//	conn->dri->close();
}

void CTAPIManager::beginTransaction(ConnectionBase *c)
{
	CTAPIConnection *conn = (CTAPIConnection *) c;
	byte cmdReq[] = {0x20,INS_REQICC,0x01,0x00,0x00}; //req ICC1, ATR return
	ByteVec resp;
	int retry = 1;
	byte SW1;
	do {
		conn->dri->performCmd(CTDAD_CT,MAKEVECTOR(cmdReq),resp,mLogger,false);
		SW1 = *(resp.end() - 2);
	} while(retry-- && SW1 == 0x64); //retry once
	if (SW1 == 0x62 ) {//already present, SPR reader does that
		conn->mForceT0 = true; //and works only with T0
		return;
		}
	if (SW1 != 0x90)
		throw CTAPIError("beginTransaction",0,resp.size(),SW1,0);
	conn->isT1 = *(--resp.end()) != 0;
}

void CTAPIManager::endTransaction(ConnectionBase *c,bool )
{
	CTAPIConnection *conn = (CTAPIConnection *) c;
	conn->dri->resetCT(1,mLogger);
	byte cmdReq[] = {0x20,INS_EJECTICC,0x01,0x04,0x00}; //EJECT ICC1, nothing returned
	ByteVec resp;
	try {
	conn->dri->performCmd(CTDAD_CT,MAKEVECTOR(cmdReq),resp,mLogger);
	} catch(CardError &) {
//		int i = 0;
	}
	conn->dri->resetCT(0,mLogger);
}

void CTAPIManager::execPinEntryCommand(ConnectionBase *c,std::vector<byte> &cmd) {
	CTAPIConnection *conn = (CTAPIConnection *) c;

	byte cmdVerify[] = {0x20,INS_VERIFY,0x01,0x00}; //verify pin on ICC1
	byte _do52[] = {0x52,0x02 + byte(cmd.size())
			,0x01,0x06};

	ByteVec do52(MAKEVECTOR(_do52));
	do52.insert(do52.end(),cmd.begin(),cmd.end());

	ByteVec command(MAKEVECTOR(cmdVerify));
	command.push_back(byte(do52.size()));
	command.insert(command.end(),do52.begin(),do52.end());

	conn->dri->performCmd(CTDAD_CT,command,mLogger);
	}

void CTAPIManager::execPinChangeCommand(ConnectionBase *c,std::vector<byte> &cmd
			,size_t oldPinLen,size_t newPinLen) {
	CTAPIConnection *conn = (CTAPIConnection *) c;

	byte cmdChange[] = {0x20,INS_MODIFY,0x01,0x00}; //change pin on ICC1
	byte _do52[] = {0x52,0x03 + byte(cmd.size())
			,0x01,0x06,byte(0x06+oldPinLen)};

	ByteVec do52(MAKEVECTOR(_do52));
	do52.insert(do52.end(),cmd.begin(),cmd.end());

	ByteVec command(MAKEVECTOR(cmdChange));
	command.push_back(byte(do52.size()));
	command.insert(command.end(),do52.begin(),do52.end());

	conn->dri->performCmd(CTDAD_CT,command,mLogger);
}

void CTAPIManager::execCommand(ConnectionBase *c,std::vector<byte> &cmd,std::vector<byte> &recv,
							   unsigned int &recvLen)
{
	CTAPIConnection *conn = (CTAPIConnection *) c;
	conn->dri->performCmd(CTDAD_ICC1,cmd,recv,mLogger,false);
	recvLen = uint(recv.size());
}

bool CTAPIManager::isT1Protocol(ConnectionBase *c)
{
	CTAPIConnection *conn = (CTAPIConnection *) c;
	if (conn->mForceT0) return false;
	return conn->isT1;
}

