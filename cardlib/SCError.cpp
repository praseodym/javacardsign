/*!
	\file		SCError.cpp
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )    
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-30 18:16:34 +0200 (N, 30 okt 2008) $
*/
// Revision $Revision: 134 $
#include "stdafx.h"
#include "SCError.h"

SCError::SCError(long err) : runtime_error("smart card API error"),error(err)
{
	std::ostringstream buf;
	switch(err) {
		case 0x80100017 : //SCARD_E_READER_UNAVAILABLE
			buf << "No smart card readers"; break;
		case 0x80100068 : //SCARD_W_RESET_CARD
		case 0x80100011 : //SCARD_E_INVALID_VALUE .. needs trapping
			buf << "Another application is using the card";break;
		default:
			buf << "exception:'" << runtime_error::what() << 
				"' code:'0x" <<std::hex << std::setfill('0') <<
				std::setw(8) << error << "'";
		}
	desc = buf.str();
}

void SCError::check(long err)
{
	if (err) 
		throw SCError(err); 
}
