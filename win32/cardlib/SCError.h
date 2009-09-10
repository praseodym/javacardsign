/*!
	\file		SCError.h
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )    
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-10-30 18:16:34 +0200 (N, 30 okt 2008) $
*/
// Revision $Revision: 134 $
#pragma once

/// Exception class for smartcard subsystem errors
/** Smartcard subsystem errors, like reader busy etc. Currently these are only
 thrown for PCSCManager, but CTAPI should derive its own from here and throw them
 as well */
class SCError :
	public std::runtime_error
{
	std::string desc;
public:
	const long error; //SC Api returns longs
	SCError(long err);
	virtual ~SCError() throw() {}
	virtual const char * what() const throw() {	return desc.c_str();} 
	static void check(long err);
};
