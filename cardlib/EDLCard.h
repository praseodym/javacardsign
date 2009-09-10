#pragma once
#include "CardBase.h"

class EDLCard: public CardBase
{
private:
	void connectToApplet();
	void checkProtocol();
	void reconnectWithT0();
	ByteVec getFile(int fileId, int length);
public:
	EDLCard(ManagerInterface &ref) : CardBase(ref) { connectToApplet(); }
	EDLCard(ManagerInterface &ref, unsigned int idx) : CardBase(ref, idx) { connectToApplet(); }
	EDLCard(ManagerInterface &ref, ConnectionBase *conn) : CardBase(ref, conn) { connectToApplet(); }
	~EDLCard() {}

	std::string getCardID();
	int authPin(std::string pin);

	ByteVec getCaCert();
	ByteVec getAuthCert();
	ByteVec getSignCert();
	ByteVec getDecCert();

	ByteVec getChallenge(byte length);
	ByteVec signData(ByteVec data, std::string pin);
	ByteVec internalAuth(ByteVec data, std::string pin);
	ByteVec rsaDecrypt(ByteVec data, std::string pin);
};