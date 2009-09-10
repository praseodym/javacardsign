// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0500	// Change this to the appropriate value to target other versions of Windows.
#endif

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS

#include "targetver.h"
#include <windows.h>
#include <CryptDlg.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>

#include <vector>
#include <sstream>
#include <iomanip>



// TODO: reference additional headers your program requires here
