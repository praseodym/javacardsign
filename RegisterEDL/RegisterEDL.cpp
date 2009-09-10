/*
 * An example use of CertSelectCertificate to display certificates on a smart card 
 *								using its CSP
 *
 * Copyright (c) 2008 Mounir IDRASSI <mounir.idrassi@idrix.fr>. All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE.
 * 
 */
#include "stdafx.h"

DWORD ShowCertsDlg(LPCTSTR szProviderName,
				  LPCTSTR szReaderName /* Can be NULL */
				  )
{
	HCRYPTPROV HMainCryptProv = NULL;
	BOOL bStatus = FALSE;
	LPTSTR szMainContainerName = NULL;
	CHAR szContainerName[1024];
	DWORD dwContainerNameLen = sizeof(szContainerName);
	DWORD dwErr = 0;
	DWORD dwFlags = CRYPT_FIRST;
	PCCERT_CONTEXT pContextArray[128];
	DWORD dwContextArrayLen = 0;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	LPBYTE pbCert = NULL;
	DWORD dwCertLen = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD pKeySpecs[2] = { AT_KEYEXCHANGE, AT_SIGNATURE};

	if (szReaderName)
	{
		size_t ulNameLen = _tcslen(szReaderName);
		szMainContainerName = (LPTSTR) LocalAlloc(0, (ulNameLen + 6) * sizeof(TCHAR));
		if (!szMainContainerName)
		{
			return GetLastError();
		}
		_stprintf(szMainContainerName, _T("\\\\.\\%s\\"), szReaderName);
	}			

	bStatus = CryptAcquireContext(&HMainCryptProv,szMainContainerName,szProviderName,PROV_RSA_FULL,0);

	if (!bStatus)
	{
		dwErr = GetLastError();
		goto end;
	}

	/* Enumerate all the containers */
	while (CryptGetProvParam(HMainCryptProv,PP_ENUMCONTAINERS,(LPBYTE) szContainerName,&dwContainerNameLen,dwFlags) &&(dwContextArrayLen < 128))
	{
#ifndef _UNICODE
		if (CryptAcquireContext(&hProv,
				szContainerName,
				szProviderName,
				PROV_RSA_FULL,
				0))
#else
		// convert the container name to unicode
		int wLen = MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, NULL, 0);
		LPWSTR szWideContainerName = (LPWSTR) LocalAlloc(0, wLen * sizeof(WCHAR));
		MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, szWideContainerName, wLen);

		// Acquire a context on the current container
		if (CryptAcquireContext(&hProv,szWideContainerName,szProviderName,PROV_RSA_FULL,0))
#endif
		{
			// Loop over all the key specs
			for (int i = 0; i < 2; i++)
			{
				if (CryptGetUserKey(hProv,pKeySpecs[i],&hKey) )
				{
					if (CryptGetKeyParam(hKey,KP_CERTIFICATE,NULL,&dwCertLen,0))
					{
						pbCert = (LPBYTE) LocalAlloc(0, dwCertLen);
						if (!pbCert)
						{
							dwErr = GetLastError();
							goto end;
						}
						if (CryptGetKeyParam(hKey,KP_CERTIFICATE,pbCert,&dwCertLen,0))
						{
							pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, pbCert,dwCertLen);
							if (pCertContext)
							{
								pContextArray[dwContextArrayLen++] = pCertContext;

								CRYPT_KEY_PROV_INFO ProvInfo;
								ProvInfo.pwszContainerName = szWideContainerName;
								ProvInfo.pwszProvName = L"Microsoft Base Smart Card Crypto Provider";
								ProvInfo.dwProvType = PROV_RSA_FULL;
								ProvInfo.dwFlags = 0;
								ProvInfo.dwKeySpec = AT_SIGNATURE;
								ProvInfo.cProvParam = 0;
								ProvInfo.rgProvParam = NULL;
								
								CertSetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID, 0, &ProvInfo);

								HCERTSTORE dest = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL,
								CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,L"My");
								if(CertAddCertificateContextToStore(dest, pCertContext,CERT_STORE_ADD_REPLACE_EXISTING, NULL))
								{
									//char certName[1024];
									//LPWSTR certName = (LPWSTR)new wchar_t[1024];
									LPTSTR certName;
									int cbSize = CertNameToStrW(pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->Subject),CERT_X500_NAME_STR,NULL,0);
									certName = (LPTSTR)malloc(cbSize * sizeof(TCHAR));

									if (CertNameToStrW(pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->Subject),CERT_X500_NAME_STR,certName,sizeof(certName)))
									{
									}
									printf("Installed certificate.");
								}
								else
									printf("Error while adding certificate to store");
							}
						}
						LocalFree(pbCert);
					}
					CryptDestroyKey(hKey);
					hKey = NULL;
				}
			}
			CryptReleaseContext(hProv, 0);
			hProv = NULL;
		}

#ifdef _UNICODE
		LocalFree(szWideContainerName);
#endif
		
		// prepare parameters for the next loop
		dwContainerNameLen = sizeof(szContainerName);
		dwFlags = 0;
	}

	if (dwContextArrayLen == 0)
		printf("No certificate contexts found on card\n");
	
end:
	while (dwContextArrayLen--)
	{
		CertFreeCertificateContext(pContextArray[dwContextArrayLen]);
	}
	if (hKey)
		CryptDestroyKey(hKey);
	if (hProv)
		CryptReleaseContext(hProv, 0);
	if (szMainContainerName)
		LocalFree(szMainContainerName);
	if (HMainCryptProv)
		CryptReleaseContext(HMainCryptProv, 0);
	return dwErr;
}


int _tmain(int argc, _TCHAR* argv[])
{
	// Register certificates on the first available smart card
	DWORD dwErr = ShowCertsDlg(_T("Microsoft Base Smart Card Crypto Provider"), NULL);
	if(dwErr)
		printf("Error while registering certificate 0x%.8X\n",dwErr);
				
	return 0;
}

