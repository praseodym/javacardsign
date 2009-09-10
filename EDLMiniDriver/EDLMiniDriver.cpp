// EDLMiniDriver.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "EDLMiniDriver.h"

#include "../cardlib/PCSCManager.h"
#include "../cardlib/SCError.h"
#include "../cardlib/EDLCard.h"

#include <algorithm>
#include <stdlib.h>
#include <crtdbg.h>
#include <fstream>
#include <string>
#include <time.h>

using std::wstring;
using std::string;
using std::runtime_error;

FILE *debugfp = NULL;
std::ofstream logStream;
std::string cachedPin;

#define DEFUN(a) a

#pragma comment(lib,"crypt32.lib")

#define KEYLEN 1024
#define _ENC_ (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#define NULLSTR(a) (a == NULL ? "<NULL>" : a)
#define NULLWSTR(a) (a == NULL ? L"<NULL>" : a)

#define CARDID_LEN 11

//#define AUTH_CONTAINER_INDEX 0
//#define SIGN_CONTAINER_INDEX 1
#define AUTH_CONTAINER_INDEX 0
#define DEC_CONTAINER_INDEX 1
#define SIGN_CONTAINER_INDEX 2

//#define AUTH_PIN_ID 1
//#define PUKK_PIN_ID 2
//#define SIGN_PIN_ID 3
#define AUTH_PIN_ID 1
#define DEC_PIN_ID 2
#define SIGN_PIN_ID 3
//#define PUKK_PIN_ID 3


typedef struct _CONTAINERMAPRECORD {
    BYTE GuidInfo[80];	// 40 x UNICODE char
    BYTE Flags;		// Bit 1 set for default container
    BYTE RFUPadding;	    
    WORD ui16SigKeySize;
    WORD ui16KeyExchangeKeySize;
} CONTAINERMAPREC;

struct cardFiles {
	BYTE file_appdir[9];	// application dir
	BYTE file_cardcf[6];	// cache file
	BYTE file_cardid[16];	// cardid file
};

LPBYTE file_cmap[sizeof(CONTAINERMAPREC)];

DWORD ret(ErrCodes a) {
	DWORD ret = a;
#ifdef DEBUG
	if (a == 0x8010001F || a == 0x0000051A || a == SCARD_E_FILE_NOT_FOUND ||
		a == 0x8010006a) {
		int k = 1;
		}
	if (a == 0x80090009 ) {
		int f = 0;
		}
	if (a != E_OK /*&& a!= 0x80100022 */) {
		int fck = 0;
		}
#endif
	if (a == E_OK) {
		dbgPrintf("return OK\n"); }
	else {
		dbgPrintf("return error 0x%08X\n",ret);
		}
	return a;
	}

// Dll Entry point
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
#ifndef DEBUG
			logStream.setstate(std::ios_base::eofbit);
#else
		{
				 _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF |
					 _CRTDBG_CHECK_ALWAYS_DF |_CRTDBG_CHECK_CRT_DF
					 |_CRTDBG_DELAY_FREE_MEM_DF |_CRTDBG_LEAK_CHECK_DF
					 );
				WCHAR _cname[MAX_PATH * 4 ] = L"\0";
				PWCHAR cname = _cname + 1;
				HMODULE caller = GetModuleHandle(NULL);
				GetModuleFileName(caller,cname,MAX_PATH);
				PWCHAR fl = (PTCHAR )cname  + lstrlen(cname) -1;
				while (isalnum(*fl) || (L'.' == *fl) || (L'_' == *fl)) fl--;
				fl++; 
				if (*fl == L'\0') return FALSE;
				if (!lstrcmpi(fl,L"explorer.exe")) return FALSE;
				if (!lstrcmpi(fl,L"lsass.exe")) return FALSE;
				if (!lstrcmpi(fl,L"winlogon.exe"))return FALSE;
				if (!lstrcmpi(fl,L"svchost.exe"))return FALSE;
				WCHAR logfile[MAX_PATH * 4];
				// Use the temp dir of the user
				GetTempPath(sizeof(logfile)/sizeof(WCHAR),logfile);

				// Hard coded directory
				//_snwprintf(logfile,MAX_PATH, L"D:\\MEDL\\svn\\trunk\\EDLMiniDriver\\Debug\\logs\\");
				
				_snwprintf(logfile + wcslen(logfile),MAX_PATH,L"edlminidriver%u.log",GetCurrentProcessId());
				debugfp = _wfopen(logfile,L"a+");
				if (!debugfp) return FALSE;
				wstring path = wstring(logfile) + L".APDU.log";
				logStream.open(path.c_str());
				dbgPrintf("DllMain:DLL_PROCESS_ATTACH %S",NULLWSTR(fl));
				}
#endif

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
#ifdef DEBUG
		if (debugfp) {dbgPrintf("DllMain:DLL_PROCESS_DETACH");fclose(debugfp);}
#endif
		break;
	}
    return TRUE;
}

/* Deprecated for Vista (and Base CSP?)
HRESULT DllRegisterServer(
						  BOOL bRegTypeLib) {
	return TRUE;
}

 
HRESULT DllUnregisterServer(BOOL bUnRegTypeLib) {
	return TRUE;
	}
*/
/*
PFN_CSP_ALLOC pfnMyCspAlloc = NULL;
PFN_CSP_REALLOC pfnMyCspReAlloc = NULL;
PFN_CSP_FREE  pfnMyCspFree = NULL;
*/

// Starting point for the minidriver. Informs the BaseCSP where to find the methods and all.
// Also some sanity checks can be performed.
DWORD WINAPI
CardAcquireContext(
    IN      PCARD_DATA  pCardData,
	__in    DWORD       dwFlags) {

	if (!pCardData) 
		return ret(E_PARAM);
	if (dwFlags) return ret(E_PARAM);

	dbgPrintf("CardAcquireContext, dwVersion=%u, name=%S"
		", hScard=0x%08X, hSCardCtx=0x%08X"
		,pCardData->dwVersion,NULLWSTR(pCardData->pwszCardName)
		,pCardData->hScard, pCardData->hSCardCtx
		);

	DWORD suppliedVersion = pCardData->dwVersion;
	if (pCardData->dwVersion < 4 && pCardData->dwVersion != 0 //COMPAT
		//|| pCardData->dwVersion > 6
		) 
		return ret(E_REVISION);

	if (suppliedVersion == 0 && pCardData->cbAtr != 0) //special case
		return ret(E_REVISION);

	//pCardData->dwVersion = 6;
	pCardData->dwVersion = (pCardData->dwVersion<6)?pCardData->dwVersion:6;

	pCardData->pfnCardDeleteContext = CardDeleteContext;
    pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
    pCardData->pfnCardDeleteContainer= CardDeleteContainer;
    pCardData->pfnCardCreateContainer= CardCreateContainer;
    pCardData->pfnCardGetContainerInfo= CardGetContainerInfo;
    pCardData->pfnCardAuthenticatePin= CardAuthenticatePin;
    pCardData->pfnCardGetChallenge= CardGetChallenge;
    pCardData->pfnCardAuthenticateChallenge= CardAuthenticateChallenge;
    pCardData->pfnCardUnblockPin= CardUnblockPin;
    pCardData->pfnCardChangeAuthenticator= CardChangeAuthenticator;
    pCardData->pfnCardDeauthenticate= NULL;// CardDeauthenticate; //CardDeauthenticate; 
    pCardData->pfnCardCreateDirectory= CardCreateDirectory;
    pCardData->pfnCardDeleteDirectory= CardDeleteDirectory;
    pCardData->pvUnused3= NULL;
    pCardData->pvUnused4= NULL;
    pCardData->pfnCardCreateFile= CardCreateFile;
    pCardData->pfnCardReadFile= CardReadFile;
    pCardData->pfnCardWriteFile= CardWriteFile;
    pCardData->pfnCardDeleteFile= CardDeleteFile;
    pCardData->pfnCardEnumFiles= CardEnumFiles;
    pCardData->pfnCardGetFileInfo= CardGetFileInfo;
    pCardData->pfnCardQueryFreeSpace= CardQueryFreeSpace;
    pCardData->pfnCardQueryKeySizes= CardQueryKeySizes;

    pCardData->pfnCardSignData= CardSignData;
    pCardData->pfnCardRSADecrypt= CardRSADecrypt;
    pCardData->pfnCardConstructDHAgreement= NULL;//CardConstructDHAgreement;

	if (suppliedVersion !=0 ) {
		/*if (NULL == pCardData->pbAtr ) return ret(E_PARAM);
		switch(pCardData->cbAtr) {
			case 26:
			case 25:
			case 18:
			case 14:
			case 13:{
				//const char ref[] = "EstEID ver 1.0";
				const char ref[] = "JCOP31V22";
				unsigned char *ptr = pCardData->pbAtr + pCardData->cbAtr - sizeof(ref) + 2;
				while(--ptr > pCardData->pbAtr)
					if (!memcmp(ref,ptr,sizeof(ref)-1)) break;
				if (ptr == pCardData->pbAtr) 
					return ret(E_WRONG_CARD);
				break;
				}
			default:
				return ret(E_PARAM);
			}*/

		if (NULL == pCardData->pwszCardName ) return ret(E_PARAM);

		if (NULL == pCardData->pfnCspAlloc) return ret(E_PARAM);
		if (NULL == pCardData->pfnCspReAlloc) return ret(E_PARAM);
		if (NULL == pCardData->pfnCspFree) return ret(E_PARAM);

		pCardData->pvVendorSpecific = pCardData->pfnCspAlloc(sizeof(cardFiles));
		BYTE empty_appdir[] = {1,'m','s','c','p',0,0,0,0};
		BYTE empty_cardcf[6]={0,0,0,0,0,0};
		BYTE empty_cardid[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_appdir,empty_appdir,sizeof(empty_appdir));
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf,empty_cardcf,sizeof(empty_cardcf));
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_cardid,empty_cardid,sizeof(empty_cardid));
/*
		if (NULL == pCardData->pfnCspCacheAddFile) return ret(E_PARAM);
		if (NULL == pCardData->pfnCspCacheLookupFile) return ret(E_PARAM);
		if (NULL == pCardData->pfnCspCacheDeleteFile) return ret(E_PARAM);
*/
		if (0 == pCardData->hScard ) return ret(E_BADHANDLE);
		//if (0 == pCardData->hSCardCtx ) return ret(E_BADHANDLE);
	}
	if (suppliedVersion > 4) {
		pCardData->pfnCardDeriveKey = NULL; //CardDeriveKey;
		pCardData->pfnCardDestroyDHAgreement = NULL; //CardDestroyDHAgreement;
		pCardData->pfnCspGetDHAgreement = NULL; //CspGetDHAgreement ;

		if (suppliedVersion > 5 ) {
			pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx; //CardDeauthenticateEx ;
			pCardData->pfnCardGetContainerProperty = CardGetContainerProperty ;
			pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
			pCardData->pfnCardGetProperty = CardGetProperty;
			pCardData->pfnCardSetProperty = CardSetProperty;
			}
		}
	return ret(E_OK);
	}


	// Exit point for the minidriver.
DWORD WINAPI
CardDeleteContext(
				  __inout     PCARD_DATA  pCardData) {
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardDeleteContext");
	if (pCardData->pvVendorSpecific)
		pCardData->pfnCspFree(pCardData->pvVendorSpecific);
	return ret(E_OK);}


DWORD WINAPI 
CardGetContainerProperty(
    __in   PCARD_DATA                                 pCardData,
    __in   BYTE                                       bContainerIndex,
    __in   LPCWSTR                                    wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
    __in   DWORD                                      cbData,
    __out  PDWORD                                     pdwDataLen,
    __in   DWORD                                      dwFlags
	) {
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardGetContainerProperty bContainerIndex=%u, wszProperty=%S"
		", cbData=%u, dwFlags=0x%08X"
		,bContainerIndex,NULLWSTR(wszProperty),cbData,dwFlags);
	if (!wszProperty) 
		return ret(E_PARAM);
	if (dwFlags) 
		return ret(E_PARAM);
	if (!pbData)
		return ret(E_PARAM);
	if (!pdwDataLen) 
		return ret(E_PARAM);

	if (wstring(CCP_PIN_IDENTIFIER) == wszProperty ) { // returns which pin identifier belongs to which container
		PPIN_ID p = (PPIN_ID) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_BUFFER);
		switch (bContainerIndex) {
			case SIGN_CONTAINER_INDEX:
				*p = SIGN_PIN_ID;
				break;
			case DEC_CONTAINER_INDEX:
				*p = DEC_PIN_ID;
				break;
			case AUTH_CONTAINER_INDEX:
				*p = AUTH_PIN_ID;
				break;
			default:
				return ret(E_NOCONTAINER);
			}
		dbgPrintf("Return Pin id %u",*p);
		return ret(E_OK);
		}

	return ret(E_PARAM);
}

DWORD WINAPI 
CardSetContainerProperty(
    __in   PCARD_DATA                                 pCardData,
    __in   BYTE                                       bContainerIndex,
    __in   LPCWSTR                                    wszProperty,
    __in_bcount(cbDataLen)  PBYTE                     pbData,
    __in   DWORD                                      cbDataLen,
    __in   DWORD                                      dwFlags
	) {
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardSetContainerProperty bContainerIndex=%u, wszProperty=%S"
		", cbDataLen=%u, dwFlags=0x%08X"
		,bContainerIndex,NULLWSTR(wszProperty),cbDataLen,dwFlags);
	return ret(E_UNSUPPORTED);
}
DWORD WINAPI 
CardGetProperty(
    __in   PCARD_DATA                                 pCardData,
    __in   LPCWSTR                                    wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
    __in   DWORD                                      cbData,
    __out  PDWORD                                     pdwDataLen,
    __in   DWORD                                      dwFlags
	) {
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardGetProperty wszProperty=%S, cbData=%u, dwFlags=%u"
		,NULLWSTR(wszProperty),cbData,dwFlags);
	if (!wszProperty) return ret(E_PARAM);
	if (!pbData) return ret(E_PARAM);
	if (!pdwDataLen) return ret(E_PARAM);

	if (wstring(CP_CARD_PIN_STRENGTH_CHANGE) == wszProperty ||
		wstring(CP_CARD_PIN_STRENGTH_UNBLOCK) == wszProperty)
		return ret(E_UNSUPPORTED);

	if (dwFlags) {
		if (wstring(CP_CARD_PIN_INFO) != wszProperty && 
			wstring(CP_CARD_PIN_STRENGTH_VERIFY) != wszProperty &&
			wstring(CP_CARD_KEYSIZES) != wszProperty) 
			return ret(E_PARAM);
		if (dwFlags > AUTH_PIN_ID ) 
			return ret(E_PARAM);
		}

	if (wstring(CP_CARD_GUID) == wszProperty) {
		PCSCManager *mgr = new PCSCManager(pCardData->hSCardCtx);
		EDLCard *card = new EDLCard(*mgr, mgr->connect(pCardData->hScard));
		card->setLogging(&logStream);
		string id = card->getCardID();
		if (id.length() != CARDID_LEN) 
		{
			dbgPrintf("runtime_error in CardReadFile id.length() is %d",id.length());
			return ret(E_NOFILE);
		}
		const char *pId = id.c_str();
		DWORD sz = 16;
		CopyMemory(pbData, pId, sz);
		*pdwDataLen = sz;
		return ret(E_OK);
	}
	if (wstring(CP_CARD_READ_ONLY) == wszProperty) {
		BOOL *p = (BOOL*)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		*p = TRUE; //HACK
		return ret(E_OK);
		}
	if (wstring(CP_CARD_CACHE_MODE) == wszProperty) {
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		//*p = CP_CACHE_MODE_SESSION_ONLY;
		*p = CP_CACHE_MODE_NO_CACHE;
		return ret(E_OK);
		}
	if (wstring(L"Supports Windows x.509 Enrollment") == wszProperty) {
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		*p = FALSE;
		return ret(E_OK);
		}
	if (wstring(CP_CARD_PIN_INFO) == wszProperty) {
		PPIN_INFO p = (PPIN_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		if (p->dwVersion != 6) return ret(E_REVISION);
		p->PinType = AlphaNumericPinType;
		p->dwFlags = 0;
		switch (dwFlags) {
			case SIGN_PIN_ID:
				dbgPrintf("returning info on PIN 0 ( Sign ) [%u]",dwFlags);
				p->PinPurpose = AuthenticationPin;
				p->PinCachePolicy.dwVersion = 6;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = 1 << (SIGN_PIN_ID) ;
				p->dwUnblockPermission = 0; //1 << (PUKK_PIN_ID);
				break;
			case DEC_PIN_ID:
				dbgPrintf("returning info on PIN 1 ( Dec ) [%u]",dwFlags);
				p->PinPurpose = DigitalSignaturePin;
				p->PinCachePolicy.dwVersion = 6;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNone;
				p->dwChangePermission = 1 << (DEC_PIN_ID) ;
				p->dwUnblockPermission = 0; //1 << (PUKK_PIN_ID);
				break;
			case AUTH_PIN_ID:
				dbgPrintf("returning info on PIN 2 ( Auth ) [%u]",dwFlags);
				p->PinPurpose = DigitalSignaturePin;
				p->PinCachePolicy.dwVersion = 6;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNone;
				p->dwChangePermission = 1 << (AUTH_PIN_ID) ;
				p->dwUnblockPermission = 0; //1 << (PUKK_PIN_ID);
				break;
			default:
				dbgPrintf("Invalid Pin number %u requested",dwFlags);
				return ret(E_PARAM);
		}
		return ret(E_OK);
	}
	if (wstring(CP_CARD_CAPABILITIES) == wszProperty ) {
		PCARD_CAPABILITIES p = (PCARD_CAPABILITIES )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		if (p->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION &&
			p->dwVersion != 0) return ret(E_REVISION);
		p->fCertificateCompression = TRUE;
		p->fKeyGen = FALSE;
		return ret(E_OK);
		}
	if (wstring(CP_CARD_PIN_STRENGTH_VERIFY) == wszProperty) {
		if (dwFlags < SIGN_PIN_ID || dwFlags > AUTH_PIN_ID) return ret(E_PARAM);
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		*p = CARD_PIN_STRENGTH_PLAINTEXT;
		return ret(E_OK);
		}

	return ret(E_PARAM);
}

DWORD WINAPI 
CardSetProperty(
    __in   PCARD_DATA                                 pCardData,
    __in   LPCWSTR                                    wszProperty,
    __in_bcount(cbDataLen)  PBYTE                     pbData,
    __in   DWORD                                      cbDataLen,
    __in   DWORD                                      dwFlags
	) {
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardSetProperty wszProperty=%S"
		", cbDataLen=%u, dwFlags=%u"
		,NULLWSTR(wszProperty),cbDataLen,dwFlags);
	if (!wszProperty) return ret(E_PARAM);

	return ret(E_UNSUPPORTED);
}

// report back some capabilities that this minidriver has to the basecsp.
DWORD WINAPI
CardQueryCapabilities(
    __in      PCARD_DATA          pCardData,
    __in      PCARD_CAPABILITIES  pCardCapabilities){
	if (!pCardData) return ret(E_PARAM);
	if (!pCardCapabilities) return ret(E_PARAM);

	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION
		&& pCardCapabilities->dwVersion != 0
		)
		return ret(E_REVISION);

	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	dbgPrintf("CardQueryCapabilities dwVersion=%u, fKeyGen=%u, fCertificateCompression=%u"
 		,pCardCapabilities->dwVersion,pCardCapabilities->fKeyGen 
		,pCardCapabilities->fCertificateCompression   );
	
	pCardCapabilities->fCertificateCompression = TRUE;
	pCardCapabilities->fKeyGen = FALSE;
	return ret(E_OK);
	}

typedef struct {
	PUBLICKEYSTRUC  publickeystruc;
	RSAPUBKEY rsapubkey;
	BYTE modulus[KEYLEN/8];
	BYTE prime1[KEYLEN/16];
	BYTE prime2[KEYLEN/16];
	BYTE exponent1[KEYLEN/16];
	BYTE exponent2[KEYLEN/16];
	BYTE coefficient[KEYLEN/16];
	BYTE privateExponent[KEYLEN/8];
} RSAPRIV;

DWORD WINAPI
CardCreateContainer(
    __in      PCARD_DATA  pCardData,
    __in      BYTE        bContainerIndex,
    __in      DWORD       dwFlags,
    __in      DWORD       dwKeySpec,
    __in      DWORD       dwKeySize,
    __in      PBYTE       pbKeyData) {
	//return ret(E_UNSUPPORTED);

	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardCreateContainer  bContainerIndex=%u, dwFlags=0x%08X"
		", dwKeySpec=%u, dwKeySize=%u"
		,bContainerIndex,dwFlags,dwKeySpec,dwKeySize);

	// todo: understand this
	if (CARD_CREATE_CONTAINER_KEY_IMPORT == dwFlags ) return ret(E_UNSUPPORTED);
	if (CARD_CREATE_CONTAINER_KEY_GEN != dwFlags ) return ret(E_PARAM);

	if (dwKeySpec != AT_SIGNATURE && dwKeySpec != AT_KEYEXCHANGE) return ret(E_UNSUPPORTED);

	if (dwKeySize != 1024) return ret(E_PARAM);

	RSAPRIV *a = (RSAPRIV*)pbKeyData;
//dwKeySpec = AT_SIGNATURE || AT_KEYEXCHANGE
	return ret(E_OK);
}


typedef struct {
	PUBLICKEYSTRUC  publickeystruc;
	RSAPUBKEY rsapubkey;
	BYTE modulus[KEYLEN/8]; 
} PUBKEYSTRUCT;

// returns back information about a certificate container.
DWORD WINAPI
CardGetContainerInfo(
    __in      PCARD_DATA  pCardData,
    __in      BYTE        bContainerIndex,
    __in      DWORD       dwFlags,
    __in      PCONTAINER_INFO pContainerInfo){
	if (!pCardData) return ret(E_PARAM);
	if (!pContainerInfo) return ret(E_PARAM);
	if (dwFlags) return ret(E_PARAM);
	if (pContainerInfo->dwVersion < 0 
		|| pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION) 
		return ret(E_REVISION);

	dbgPrintf("CardGetContainerInfo bContainerIndex=%u, dwFlags=0x%08X, dwVersion=%u"
		", cbSigPublicKey=%u, cbKeyExPublicKey=%u"
		,bContainerIndex,dwFlags , pContainerInfo->dwVersion 
		,pContainerInfo->cbSigPublicKey, pContainerInfo->cbKeyExPublicKey 
		);

	if(bContainerIndex != SIGN_CONTAINER_INDEX && bContainerIndex != DEC_CONTAINER_INDEX && bContainerIndex != AUTH_CONTAINER_INDEX)
		return ret(E_NOCONTAINER);
	
	PUBKEYSTRUCT oh;
	DWORD sz = sizeof(oh);
	
	// try to fetch the corresponding certificate
	try
	{
		ByteVec reply;
		
		PCSCManager *mgr = new PCSCManager(pCardData->hSCardCtx);
		EDLCard *card = new EDLCard(*mgr, mgr->connect(pCardData->hScard));
		card->setLogging(&logStream);

		switch(bContainerIndex)
		{
			case AUTH_CONTAINER_INDEX:
				reply = card->getAuthCert();
				break;
			case DEC_CONTAINER_INDEX:
				reply = card->getDecCert();
				break;
			case SIGN_CONTAINER_INDEX:
				reply = card->getSignCert();
				break;
		}

		int len = 0;
		if(reply.size() >= 4) // really should be
			len = (reply[2] << 8) + (reply[3] & 0xFF) + 4;
		//reply.resize(len);

		PCCERT_CONTEXT cer = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING ,
			&reply[0],(DWORD) len);
		PCERT_PUBLIC_KEY_INFO pinf = &(cer->pCertInfo->SubjectPublicKeyInfo);
		CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING ,
			RSA_CSP_PUBLICKEYBLOB, pinf->PublicKey.pbData , pinf->PublicKey.cbData ,
			0, (LPVOID) &oh, &sz);
	}
	catch(runtime_error & ex) 
	{
		dbgPrintf("runtime_error exception thrown:", ex.what());
		return ret(E_INTERNAL);
	}

	if (bContainerIndex == SIGN_CONTAINER_INDEX || bContainerIndex == AUTH_CONTAINER_INDEX) {
		oh.publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
		// exchange key (for encryption and decryption)
		pContainerInfo->cbKeyExPublicKey = 0;
		pContainerInfo->pbKeyExPublicKey = NULL;
		// signing key
		pContainerInfo->cbSigPublicKey = sz;//0;sz;
		pContainerInfo->pbSigPublicKey = (PBYTE)(*pCardData->pfnCspAlloc)(sz);//NULL;(PBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!pContainerInfo->pbSigPublicKey) return ret(E_MEMORY);
		CopyMemory(pContainerInfo->pbSigPublicKey,&oh,sz);
		dbgPrintf("return info on SIGN_CONTAINER_INDEX (or AUTH_CONTAINER_INDEX)");
		}
	else if(bContainerIndex == DEC_CONTAINER_INDEX) {
		oh.publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
		// exchange key (for encryption and decryption)
		pContainerInfo->cbKeyExPublicKey = sz;
		pContainerInfo->pbKeyExPublicKey = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!pContainerInfo->pbKeyExPublicKey) return ret(E_MEMORY);
		CopyMemory(pContainerInfo->pbKeyExPublicKey,&oh,sz);
		// signing key
		pContainerInfo->cbSigPublicKey = 0;//0;sz;
		pContainerInfo->pbSigPublicKey = NULL;//NULL;(PBYTE)(*pCardData->pfnCspAlloc)(sz);
		
		dbgPrintf("return info on DEC_CONTAINER_INDEX");
	}

	pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;
	return ret(E_OK);
}

// Check the pincode that the user has entered at the basecsp.
DWORD WINAPI
CardAuthenticatePin(
    __in                   PCARD_DATA  pCardData,
    __in                   LPWSTR      pwszUserId,
    __in_bcount(cbPin)     PBYTE       pbPin,
    __in                   DWORD       cbPin,
    __out_opt              PDWORD pcAttemptsRemaining){
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardAuthenticatePin pwszUserId=%S, cbPin=%u"
		,NULLWSTR(pwszUserId),cbPin);

	if (NULL == pwszUserId) return ret(E_PARAM);
	if (wstring(wszCARD_USER_USER) != pwszUserId &&
		wstring(wszCARD_USER_ADMIN) != pwszUserId
		) return ret(E_PARAM);

	if (NULL == pbPin) return ret(E_PARAM);

	// pin length between 4 and 12
	if (cbPin < 4 || cbPin > 12) return ret(E_WRONGPIN);

	char *pin = (char *)pbPin;
	string pinString(pin , pin+cbPin );

	try
	{
		PCSCManager *mgr = new PCSCManager(pCardData->hSCardCtx);
		EDLCard *card = new EDLCard(*mgr, mgr->connect(pCardData->hScard));
		card->setLogging(&logStream);

		int reply = card->authPin(pinString);
		if(reply == 0xFF) // pin OK!
		{
			cachedPin = pin; // save it!
			return ret(E_OK);
		}

		*pcAttemptsRemaining = reply;
		if(reply > 0) // still attempts remaining
			return ret(E_WRONGPIN);
		else // no attempt remaining card is blocked
			return ret(E_PINBLOCKED);
	}
	catch (std::runtime_error &err ) 
	{
		dbgPrintf("runtime_error in CardAuthenticatePin '%s'",err.what());
		return ret(E_INTERNAL);
	}

	return ret(E_INTERNAL); // something went wrong we should've returned earlier
	}

DWORD WINAPI 
CardAuthenticateEx(
    __in   PCARD_DATA                             pCardData,
    __in   PIN_ID                                 PinId,
    __in   DWORD                                  dwFlags,
    __in   PBYTE                                  pbPinData,
    __in   DWORD                                  cbPinData,
    __deref_out_bcount_opt(*pcbSessionPin) PBYTE  *ppbSessionPin,
    __out_opt PDWORD                              pcbSessionPin,
	__out_opt PDWORD                              pcAttemptsRemaining
	) {
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s"
		,PinId,dwFlags,cbPinData,pcAttemptsRemaining ? "YES" : "NO");

	if (NULL == pbPinData) return ret(E_PARAM);

	// TODO: actually check the pin with the card
	return ret(E_OK);
}


DWORD WINAPI
CardEnumFiles(
    __in      PCARD_DATA  pCardData,
    __in      LPSTR       pszDirectoryName,
    __out_ecount(*pdwcbFileName)
              LPSTR      *pmszFileNames,
    __out     LPDWORD     pdwcbFileName,
    __in      DWORD       dwFlags
	){
	dbgPrintf("CardEnumFiles pszDirectoryName=%s"
		,NULLSTR(pszDirectoryName));
	const char root_files[] = "cardapps\0cardcf\0cardid\0\0";
	const char mscp_files[] = "kxc00\0kxc01\0cmapfile\0\0";
	if (!pCardData) return ret(E_PARAM);
	if (!pmszFileNames) return ret(E_PARAM);
	if (!pdwcbFileName) return ret(E_PARAM);
	if (dwFlags) return ret(E_PARAM);

	return ret(E_UNSUPPORTED);
	}


DWORD WINAPI
CardGetFileInfo(
    __in         PCARD_DATA  pCardData,
    __in         LPSTR      pszDirectoryName,
    __in         LPSTR      pszFileName,
    __in         PCARD_FILE_INFO pCardFileInfo
	){
	dbgPrintf("CardGetFileInfo pszDirectoryName=%s, pszFileName=%s"
		,NULLSTR(pszDirectoryName),NULLSTR(pszFileName));
	if (!pCardData) return ret(E_PARAM);
	if (!pszFileName) return ret(E_PARAM);
	if (!strlen(pszFileName)) return ret(E_PARAM);
	if (!pCardFileInfo) return ret(E_PARAM);

	if (pCardFileInfo->dwVersion != CARD_FILE_INFO_CURRENT_VERSION && 
		pCardFileInfo->dwVersion != 0 ) 
		return ret(E_REVISION);

	return ret(E_UNSUPPORTED);
}

// reads a file from the smartcard.
DWORD WINAPI
CardReadFile(
    __in                             PCARD_DATA  pCardData,
    __in                             LPSTR       pszDirectoryName,
    __in                             LPSTR       pszFileName,
    __in                             DWORD       dwFlags,
    __deref_out_bcount(*pcbData)     PBYTE      *ppbData,
    __out                            PDWORD      pcbData){
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardReadFile pszDirectoryName=%s, pszFileName=%s, dwFlags=0x%08X"
		,NULLSTR(pszDirectoryName),NULLSTR(pszFileName),dwFlags);
	if (!pszFileName) return ret(E_PARAM);
	if (!strlen(pszFileName)) return ret(E_PARAM);
	if (!ppbData) 
		return ret(E_PARAM);
	if (!pcbData) 
		return ret(E_PARAM);
	if (dwFlags) 
		return ret(E_PARAM);

	if(!_strcmpi(pszFileName,"cardid")) {
		try
		{
			PCSCManager *mgr = new PCSCManager(pCardData->hSCardCtx);
			EDLCard *card = new EDLCard(*mgr, mgr->connect(pCardData->hScard));
			card->setLogging(&logStream);
			string id = card->getCardID();
			if (id.length() != CARDID_LEN) 
			{
				dbgPrintf("runtime_error in CardReadFile id.length() is %d",id.length());
				return ret(E_NOFILE);
			}
			
			const char *pId = id.c_str();
			DWORD sz = 16;
			PBYTE t = (PBYTE) (*pCardData->pfnCspAlloc)(sz);
			if (!t) return ret(E_MEMORY);
			CopyMemory(t, pId, sz);
			ppbData = &t;
			pcbData = &sz;
			return ret(E_OK);
		}
		catch (std::runtime_error &err ) 
		{
			dbgPrintf("runtime_error in CardReadFile '%s'",err.what());
			return ret(E_NOFILE);
		}
		return SCARD_E_FILE_NOT_FOUND;
	}
	if(!_strcmpi(pszFileName,"cardcf")) {
		DWORD sz = sizeof(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf);
		PBYTE t = (LPBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!t) return ret(E_MEMORY);
		CopyMemory(t,((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf,sz);
		*ppbData = t;
		*pcbData = sz;
		return ret(E_OK);
	}
	if (pszDirectoryName && !_strcmpi(pszDirectoryName,"mscp")) {
		if (!_strcmpi(pszFileName,"cmapfile")) {
			int numContainers = 3;
			DWORD sz = sizeof(CONTAINERMAPREC) * numContainers;
			//DWORD sz = sizeof(CONTAINERMAPREC);
			PBYTE t = (LPBYTE)(*pCardData->pfnCspAlloc)(sz);
			if (!t) return ret(E_MEMORY);
			PBYTE originalT = t;
			ZeroMemory(t,sz);

			CONTAINERMAPREC *c1 = (CONTAINERMAPREC *)t;
			wcsncpy((PWCHAR) c1->GuidInfo, L"00000000000_AUT", sizeof(c1->GuidInfo) /2);
			c1->Flags = 3; // 1 valid + 2 default
			c1->ui16KeyExchangeKeySize = 0;
			c1->ui16SigKeySize = 1024; // 1024

			if(numContainers > 1)
			{
				CONTAINERMAPREC *c2 = (CONTAINERMAPREC *) (t + sizeof(CONTAINERMAPREC));
				wcsncpy((PWCHAR) c2->GuidInfo, L"00000000000_DEC", sizeof(c2->GuidInfo) /2);
				c2->Flags = 1; // 1 valid + 2 default
				c2->ui16KeyExchangeKeySize = 1024;
				c2->ui16SigKeySize = 0; // 1024
			}
			if(numContainers > 2)
			{
				CONTAINERMAPREC *c3 = (CONTAINERMAPREC *) (t + sizeof(CONTAINERMAPREC)*2);
				wcsncpy((PWCHAR) c3->GuidInfo, L"00000000000_SIG", sizeof(c3->GuidInfo) /2);
				c3->Flags = 1; // 1 valid + 2 default
				c3->ui16KeyExchangeKeySize = 0;
				c3->ui16SigKeySize = 1024; // 1024
			}

			*ppbData = originalT;
			*pcbData = sz;
			return ret(E_OK);
		}
		// ksc00: example key signature cert 0
		// kxc01: example key exchange cert 1
		if (!_strcmpi(pszFileName,"ksc00") || !_strcmpi(pszFileName,"kxc01") || !_strcmpi(pszFileName,"ksc02") ) { 
			ByteVec reply;
			try {
				PCSCManager *mgr = new PCSCManager(pCardData->hSCardCtx);
				EDLCard *card = new EDLCard(*mgr, mgr->connect(pCardData->hScard));
				card->setLogging(&logStream);
				if (!_strcmpi(pszFileName,"ksc00"))
					reply = card->getAuthCert();
				else if (!_strcmpi(pszFileName,"kxc01"))
					reply = card->getDecCert();
				else if (!_strcmpi(pszFileName,"ksc02"))
					reply = card->getSignCert();
			} catch (runtime_error & err) {
				dbgPrintf("runtime_error in CardReadFile, reading kxc00, '%s'",err.what());
				return ret(E_NOFILE);
			}

			DWORD sz = (DWORD) reply.size();
			PBYTE t= (PBYTE)(*pCardData->pfnCspAlloc)(sz);
			if(!t) return ret(E_MEMORY);
			CopyMemory(t, &reply[0], sz);
			*ppbData = t;
			*pcbData = sz;
			return ret(E_OK);
		}
	}
	dbgPrintf("returning E_NOFILE");
	return ret(E_NOFILE);
	}


DWORD WINAPI
CardWriteFile(
    __in                     PCARD_DATA  pCardData,
    __in                     LPSTR       pszDirectoryName,
    __in                     LPSTR       pszFileName,
    __in                     DWORD       dwFlags,
    __in_bcount(cbData)      PBYTE       pbData,
    __in                     DWORD       cbData){
	if (!pCardData) return ret(E_PARAM);
	dbgPrintf("CardWriteFile pszDirectoryName=%s, pszFileName=%s, dwFlags=0x%08X, cbData=%u"
		,NULLSTR(pszDirectoryName),NULLSTR(pszFileName),dwFlags,cbData);

	if (!strcmp(pszFileName,"cardcf")) {
		DWORD sz = sizeof(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf);
		if (cbData > sz) return ret(E_CARDFULL);
		CopyMemory(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf,pbData,cbData);
		return ret(E_OK);
	}
	return ret(E_INTERNAL);
}


DWORD WINAPI
CardQueryFreeSpace(
    __in      PCARD_DATA  pCardData,
    __in      DWORD       dwFlags,
    __in      PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo) {
	if (!pCardData) 
		return ret(E_PARAM);
	if (!pCardFreeSpaceInfo) 
		return ret(E_PARAM);
	dbgPrintf("CardWriteFile dwFlags=0x%08X, dwVersion=%u"
		, dwFlags , pCardFreeSpaceInfo->dwVersion );
	if (dwFlags) 
		return ret(E_PARAM);

	return ret(E_UNSUPPORTED);
	}

DWORD WINAPI
CardQueryKeySizes(
    __in      PCARD_DATA  pCardData,
    __in      DWORD       dwKeySpec,
    __in      DWORD       dwFlags,
    __in      PCARD_KEY_SIZES pKeySizes){
	if (!pCardData)
		return ret(E_PARAM);
	if (!pKeySizes) {
		dbgPrintf("CardQueryKeySizes NULL pKeySizes");
		return ret(E_PARAM);
		}
	dbgPrintf("CardQueryKeySizes dwKeySpec=%u, dwFlags=0x%08X, dwVersion=%u"
		,dwKeySpec,dwFlags,pKeySizes->dwVersion );
	if (dwFlags) return  ret(E_PARAM);
	if (dwKeySpec > 8 || dwKeySpec == 0 ) return ret(E_PARAM);
	if (dwKeySpec != AT_SIGNATURE && 
		dwKeySpec != AT_KEYEXCHANGE ) {	
		return ret(E_UNSUPPORTED);
		}
	if (pKeySizes->dwVersion > CARD_KEY_SIZES_CURRENT_VERSION) 
		return ret(E_REVISION);

	// TODO: UPDATE
//	pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	pKeySizes->dwDefaultBitlen = 1024;
	pKeySizes->dwMaximumBitlen = 1024;
	pKeySizes->dwMinimumBitlen = 1024;
	pKeySizes->dwIncrementalBitlen = 0;
	return ret(E_OK);
}

DWORD WINAPI
CardRSADecrypt(
    __in        PCARD_DATA              pCardData,
    __inout     PCARD_RSA_DECRYPT_INFO  pInfo){
	if (!pCardData) return ret(E_PARAM);
	if (!pInfo) return ret(E_PARAM);
	dbgPrintf("CardRSADecrypt dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u"
		,pInfo->dwVersion,pInfo->bContainerIndex , pInfo->dwKeySpec);

	if (pInfo->dwVersion != CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION) 
		return ret(E_REVISION);

	if (pInfo->dwKeySpec > 8 || pInfo->dwKeySpec == 0 ) 
		return ret(E_PARAM);
	if (pInfo->dwKeySpec != AT_SIGNATURE && pInfo->dwKeySpec != AT_KEYEXCHANGE ) {	
		return ret(E_PARAM);
		}
	if (pInfo->bContainerIndex != DEC_CONTAINER_INDEX)
		return ret(E_NOCONTAINER);

	if (pInfo->bContainerIndex == DEC_CONTAINER_INDEX ) {
		if (pInfo->dwKeySpec != AT_KEYEXCHANGE) return ret(E_PARAM);
		}
	else 
		if (pInfo->dwKeySpec != AT_SIGNATURE) return ret(E_PARAM);

	if (!pInfo->pbData)
		return ret(E_PARAM);
	if (pInfo->cbData < 1024 / 8) 
		return ret(E_SCBUFFER);

	#ifdef DEBUG 
	dbgPrintf("pInfo->bContainerIndex=%i, pInfo->dwKeySpec=%i, pInfo->dwVersion=%i",
		pInfo->bContainerIndex, pInfo->dwKeySpec, pInfo->dwVersion);
	for(unsigned int j=0;j < pInfo->cbData;j++) {
		if (!(j % 16)) fprintf(debugfp,"\n");
		fprintf(debugfp,"0x%02X, ",pInfo->pbData[j]);
		}
	fprintf(debugfp,"\n");
	#endif

	ByteVec reply;
	try {
		dbgPrintf("Decrypt\n");
		ByteVec cryptedMessage(pInfo->pbData ,pInfo->pbData + pInfo->cbData ); 
		dbgPrintf("Incoming Message:\n");
		for(int i=0;i<cryptedMessage.size();i++)
			fprintf(debugfp,"%02X",cryptedMessage[i]);
			//fprintf(debugfp,"0x%02X, ",cryptedMessage[i]);
		fprintf(debugfp,"\n\n");
		reverse(cryptedMessage.begin(),cryptedMessage.end()); // reverse because of LSB
		dbgPrintf("Reversed Message:\n");
		for(int i=0;i<cryptedMessage.size();i++)
			fprintf(debugfp,"%02X",cryptedMessage[i]);
		fprintf(debugfp,"\n\n");
		PCSCManager *mgr = new PCSCManager(pCardData->hSCardCtx);
		EDLCard *card = new EDLCard(*mgr, mgr->connect(pCardData->hScard));
		card->setLogging(&logStream);
		
		reply = card->rsaDecrypt(cryptedMessage, cachedPin);
		dbgPrintf("Reply:\n");
		for(int i=0;i<reply.size();i++)
			fprintf(debugfp,"%02X",reply[i]);
		fprintf(debugfp,"\n\n");
	}
	catch (runtime_error & ex) {
		dbgPrintf("runtime_error exception thrown: %s", ex.what());
		return ret(E_INTERNAL);
		}

	//our data comes out in wrong order and needs to be repadded
	int psLen = (int )(128 - reply.size() - 3);
	ByteVec pB(0);

	srand((unsigned int)time(0));
	reverse(reply.begin(),reply.end());
	pB.insert(pB.end(),reply.begin(),reply.end());
	pB.push_back(0);
	for (;psLen > 0;psLen --) {
		BYTE br;
		while(0 == (br = LOBYTE(rand())));
		pB.push_back( br );
		}
	pB.push_back(2);
	pB.push_back(0);

	if (pInfo->cbData != pB.size()) {
		dbgPrintf("invalid condition in CardRSADecrypt");
		return ret(E_INTERNAL);
		}
	//CopyMemory(pInfo->pbData,&reply[0],reply.size());
	CopyMemory(pInfo->pbData,&pB[0],pB.size());

	return ret(E_OK);
	}

DWORD WINAPI
CardSignData(
    __in      PCARD_DATA          pCardData,
    __in      PCARD_SIGNING_INFO  pInfo){
	if (!pCardData) return ret(E_PARAM);
	if (!pInfo) return ret(E_PARAM);

	dbgPrintf("CardSignData dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u"
		", dwSigningFlags=0x%08X, aiHashAlg=0x%08X, cbData=%u"
		,pInfo->dwVersion,pInfo->bContainerIndex , pInfo->dwKeySpec
		,pInfo->dwSigningFlags,pInfo->aiHashAlg, pInfo->cbData  );

	ALG_ID hashAlg = pInfo->aiHashAlg;

	// a lot of sanity checks
	if (!pInfo->pbData) return ret(E_PARAM);
	if (pInfo->bContainerIndex != SIGN_CONTAINER_INDEX && pInfo->bContainerIndex != AUTH_CONTAINER_INDEX)
		return ret(E_NOCONTAINER);

	if (pInfo->dwVersion > 1) {
		dbgPrintf("CardSignData(3) dwPaddingType=%u",pInfo->dwPaddingType);
		}

	if (pInfo->dwVersion != 1 && pInfo->dwVersion != 2)  {
		dbgPrintf("unsupported version ");
		return ret(E_REVISION);
		}
	if (pInfo->dwKeySpec != AT_KEYEXCHANGE && pInfo->dwKeySpec != AT_SIGNATURE ) {
		dbgPrintf("unsupported dwKeySpec");
		return ret(E_PARAM);
		}

	// algorithm and padding checks
	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags) {
		if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType) {
			dbgPrintf("unsupported paddingtype");
			return ret(E_UNSUPPORTED);
			}
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO *)pInfo->pPaddingInfo;
		if (!pinf->pszAlgId) 
			hashAlg = CALG_SSL3_SHAMD5;
		else {
			if (pinf->pszAlgId == wstring(L"MD5"))  hashAlg = CALG_MD5;
			if (pinf->pszAlgId == wstring(L"SHA1"))  hashAlg = CALG_SHA1;
			}
		}
	else {
		if (GET_ALG_CLASS(hashAlg) != ALG_CLASS_HASH) {
			dbgPrintf("bogus aiHashAlg");
			return ret(E_PARAM);
			}
		if (hashAlg !=0 && hashAlg != CALG_SSL3_SHAMD5 &&
			hashAlg != CALG_SHA1 && hashAlg != CALG_MD5
			) {
			dbgPrintf("unsupported aiHashAlg");
			return ret(E_UNSUPPORTED);
			}
		}

	DWORD sz = 1024/ 8;
	ByteVec reply;

	if (hashAlg == CALG_SHA1) dbgPrintf("CALCULATE SHA1");
	if (hashAlg == CALG_MD5) dbgPrintf("CALCULATE MD5");
	if (hashAlg == CALG_SSL3_SHAMD5) dbgPrintf("CALCULATE CALG_SSL3_SHAMD5");

	ByteVec data(pInfo->pbData ,pInfo->pbData + pInfo->cbData );
	bool withOID = (pInfo->dwSigningFlags & CRYPT_NOHASHOID) ? false : true;
	try  {
		PCSCManager *mgr = new PCSCManager(pCardData->hSCardCtx);
		EDLCard *card = new EDLCard(*mgr, mgr->connect(pCardData->hScard));
		card->setLogging(&logStream);
		//if (hashAlg == CALG_SHA1 || hashAlg == CALG_SSL3_SHAMD5)
		if(pInfo->bContainerIndex == AUTH_CONTAINER_INDEX)
			reply = card->internalAuth(data, cachedPin);
		else if(pInfo->bContainerIndex == SIGN_CONTAINER_INDEX)
			reply = card->signData(data, cachedPin);
	}
	catch (runtime_error & ex) {
		dbgPrintf("runtime_error exception thrown: %s", ex.what());
		return ret(E_INTERNAL);
	}

	reverse(reply.begin(),reply.end());

	pInfo->cbSignedData = (DWORD) reply.size();
	if (!(pInfo->dwSigningFlags & CARD_BUFFER_SIZE_ONLY)) {
		pInfo->pbSignedData = (PBYTE)(*pCardData->pfnCspAlloc)(reply.size());
		if (!pInfo->pbSignedData) return ret(E_MEMORY);
		CopyMemory(pInfo->pbSignedData,&reply[0],reply.size());
		}
	return ret(E_OK);
}

DWORD WINAPI
CardDeauthenticate(
    __in    PCARD_DATA  pCardData,
    __in    LPWSTR      pwszUserId,
    __in    DWORD       dwFlags
	){
	dbgPrintf("CardDeauthenticate:dummy");
	// TODO: actually de-authenticate
	return ret(E_OK);

	}

DWORD WINAPI CardDeauthenticateEx(
    __in   PCARD_DATA                             pCardData,
    __in   PIN_SET                                PinId,
	__in   DWORD                                  dwFlags
	) {
	dbgPrintf("CardDeauthenticateEx:dummy");
	// TODO: actually de-authenticate
	return ret(E_OK);
}
