#include "stdafx.h"
#include "EDLMiniDriver.h"

DWORD WINAPI
CardDeleteContainer(
    __in      PCARD_DATA  pCardData,
    __in      BYTE        bContainerIndex,
    __in      DWORD       dwReserved
	){
	dbgPrintf("CardDeleteContainer:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardUnblockPin(
    __in                               PCARD_DATA  pCardData,
    __in                               LPWSTR      pwszUserId,
    __in_bcount(cbAuthenticationData)  PBYTE       pbAuthenticationData,
    __in                               DWORD       cbAuthenticationData,
    __in_bcount(cbNewPinData)          PBYTE       pbNewPinData,
    __in                               DWORD       cbNewPinData,
    __in                               DWORD       cRetryCount,
    __in                               DWORD       dwFlags
	){
	dbgPrintf("CardUnblockPin:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardChangeAuthenticator(
    __in                                 PCARD_DATA  pCardData,
    __in                                 LPWSTR      pwszUserId,
    __in_bcount(cbCurrentAuthenticator)  PBYTE       pbCurrentAuthenticator,
    __in                                 DWORD       cbCurrentAuthenticator,
    __in_bcount(cbNewAuthenticator)      PBYTE       pbNewAuthenticator,
    __in                                 DWORD       cbNewAuthenticator,
    __in                                 DWORD       cRetryCount,
    __in                                 DWORD       dwFlags,
    __out_opt                            PDWORD pcAttemptsRemaining
	){
	dbgPrintf("CardChangeAuthenticator:dummy");
	return ret(E_UNSUPPORTED);}


DWORD WINAPI
CardCreateDirectory(
    __in    PCARD_DATA  pCardData,
    __in    LPSTR       pszDirectoryName,
    __in    CARD_DIRECTORY_ACCESS_CONDITION AccessCondition
	){
	dbgPrintf("CardCreateDirectory:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardDeleteDirectory(
    __in    PCARD_DATA  pCardData,
    __in    LPSTR       pszDirectoryName
	){
	dbgPrintf("CardDeleteDirectory:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardCreateFile(
    __in    PCARD_DATA  pCardData,
    __in    LPSTR       pszDirectoryName,
    __in    LPSTR       pszFileName,
    __in    DWORD       cbInitialCreationSize,
    __in    CARD_FILE_ACCESS_CONDITION AccessCondition
	){
	dbgPrintf("CardCreateFile:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardDeleteFile(
    __in    PCARD_DATA  pCardData,
    __in    LPSTR       pszDirectoryName,
    __in    LPSTR       pszFileName,
    __in    DWORD       dwFlags
	){
	dbgPrintf("CardDeleteFile:dummy");
	return ret(E_UNSUPPORTED);}


//challenge only
DWORD WINAPI
CardConstructDHAgreement(
    __in     PCARD_DATA pCardData,
    __in     PCARD_DH_AGREEMENT_INFO pAgreementInfo
	){
	dbgPrintf("CardConstructDHAgreement:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardDeriveKey(
    __in     PCARD_DATA pCardData,
    __in     PCARD_DERIVE_KEY pAgreementInfo
	){
	dbgPrintf("CardDeriveKey:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardDestroyDHAgreement(
    __in PCARD_DATA pCardData,
    __in BYTE       bSecretAgreementIndex,
    __in DWORD      dwFlags
	){
	dbgPrintf("CardDestroyDHAgreement:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI CspGetDHAgreement(
    __in  PCARD_DATA           pCardData,
    __in  PVOID                hSecretAgreement,
    __out BYTE*                pbSecretAgreementIndex,
    __in  DWORD                dwFlags
	){
	dbgPrintf("CspGetDHAgreement:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardGetChallenge(
    __in                                  PCARD_DATA pCardData,
    __deref_out_bcount(*pcbChallengeData) PBYTE     *ppbChallengeData,
    __out                                 PDWORD     pcbChallengeData
	){
	dbgPrintf("CardGetChallenge:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI
CardAuthenticateChallenge(
    __in                             PCARD_DATA  pCardData,
    __in_bcount(cbResponseData)      PBYTE       pbResponseData,
    __in                             DWORD       cbResponseData,
    __out_opt                        PDWORD pcAttemptsRemaining
	){
	dbgPrintf("CardAuthenticateChallenge:dummy");
	return ret(E_UNSUPPORTED);}

//VER 6 only
DWORD
WINAPI
CardGetChallengeEx(
    __in                                  PCARD_DATA pCardData,
    __in                                  PIN_ID     PinId,
    __deref_out_bcount(*pcbChallengeData) PBYTE     *ppbChallengeData,
    __out                                 PDWORD     pcbChallengeData,
	__in                                  DWORD      dwFlags
	){
	dbgPrintf("CardGetChallengeEx:dummy");
	return ret(E_UNSUPPORTED);}

DWORD WINAPI CardChangeAuthenticatorEx(
    __in   PCARD_DATA                             pCardData,
    __in   DWORD                                  dwFlags,
    __in   PIN_ID                                 dwAuthenticatingPinId,
    __in_bcount(cbAuthenticatingPinData) PBYTE     pbAuthenticatingPinData,
    __in   DWORD                                  cbAuthenticatingPinData,
    __in   PIN_ID                                 dwTargetPinId,
    __in_bcount(cbTargetData)     PBYTE     pbTargetData,
    __in   DWORD                                  cbTargetData,
    __in   DWORD                                  cRetryCount,
	__out_opt PDWORD                              pcAttemptsRemaining
	) {
	dbgPrintf("CardChangeAuthenticatorEx:dummy");
	return ret(E_UNSUPPORTED);}

