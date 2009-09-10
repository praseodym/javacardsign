/*!
	\file		EstEidCardMaintainer.h
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )    
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-28 14:47:24 +0200 (T, 28 okt 2008) $
*/
// Revision $Revision: 132 $
#pragma once
#include "EstEidCard.h"

/// Estonian ID card maintaier class, for generating keys and replacing certificates
class EstEidCardMaintainer {
	EstEidCard card;
public:
	EstEidCardMaintainer(EstEidCard &ref) : card(ref) {}
	~EstEidCardMaintainer() {}
	/// generate a new key pair
	void performGenerateNewKeys();
	};
