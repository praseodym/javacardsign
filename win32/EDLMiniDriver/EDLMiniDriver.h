// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the EDLMINIDRIVER_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// EDLMINIDRIVER_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.

#include <cardmod.h>
#include <stdio.h>

extern FILE *debugfp;

#ifdef DEBUG 
#define dbgPrintf(...) {fprintf(debugfp,__VA_ARGS__); \
		fprintf(debugfp,"\n");fflush(debugfp);}
#else
#define dbgPrintf(...) {}
#endif

typedef enum {
	E_OK = NO_ERROR,
	E_MEMORY = ERROR_NOT_ENOUGH_MEMORY,
	E_BUFFER = ERROR_INSUFFICIENT_BUFFER,
	E_SCBUFFER = SCARD_E_INSUFFICIENT_BUFFER,
	E_REVISION = ERROR_REVISION_MISMATCH,
	E_PARAM = SCARD_E_INVALID_PARAMETER,
	E_BADHANDLE = SCARD_E_INVALID_HANDLE,
	E_UNSUPPORTED = SCARD_E_UNSUPPORTED_FEATURE,
	E_NOCONTAINER = SCARD_E_NO_KEY_CONTAINER,
	E_WRONGPIN = SCARD_W_WRONG_CHV,
	E_PINBLOCKED = SCARD_W_CHV_BLOCKED,
	E_NOFILE = SCARD_E_FILE_NOT_FOUND,
	E_CARDFULL = SCARD_E_WRITE_TOO_MANY,
	E_INTERNAL = SCARD_E_UNEXPECTED,
	E_WRONG_CARD = SCARD_E_UNKNOWN_CARD,
	E_NODIRECTORY= SCARD_E_DIR_NOT_FOUND,
	E_NEEDSAUTH = SCARD_W_SECURITY_VIOLATION,
	E_BADDATA = NTE_BAD_DATA,
} ErrCodes;

DWORD ret(ErrCodes a);
