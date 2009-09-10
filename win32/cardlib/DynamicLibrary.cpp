/*!
	\file		DynamicLibrary.cpp
	\copyright	(c) Kaido Kert ( kaidokert@gmail.com )
	\licence	BSD
	\author		$Author: kaidokert $
	\date		$Date: 2008-11-14 04:07:40 +0200 (R, 14 nov 2008) $
*/
// Revision $Revision: 144 $
#include "stdafx.h"
#include "DynamicLibrary.h"

DynamicLibrary::DynamicLibrary(const char *dllName) :
	name(dllName),m_pathHint("") {
	construct();
	}

DynamicLibrary::DynamicLibrary(const char *dllName,int version) :
	name(dllName),m_pathHint("") {
	construct(version);
	}

#ifdef WIN32
#include <windows.h>
#pragma comment(lib,"version")

void DynamicLibrary::construct(int ) {
	mLibhandle = LoadLibraryA(name.c_str());
	if (!mLibhandle) {
		std::ostringstream buf;
		buf << "Dynamic library '" << name << "' not found in system";
		throw std::runtime_error(buf.str());
		}
	}

DynamicLibrary::~DynamicLibrary() {
	FreeLibrary((HMODULE)mLibhandle);
	}

DynamicLibrary::fProc DynamicLibrary::getProc(const char *procName) {
	fProc proc =(fProc) GetProcAddress((HMODULE)mLibhandle,procName);
	if (!proc) throw std::runtime_error("proc not found");
	return proc;
	}

std::string DynamicLibrary::getVersionStr() {
	std::string ret = "missing";
	DWORD infoHandle;
	LONG sz = GetFileVersionInfoSizeA(name.c_str(),&infoHandle);
	if (!sz) return ret;

	VS_FIXEDFILEINFO * fileInf;
	std::vector<BYTE> buf(sz*2);
	if (!GetFileVersionInfoA(name.c_str(),0,sz,&buf[0])) return ret;
	UINT len;
	if (!VerQueryValueA(&buf[0],"\\",(LPVOID *) &fileInf,&len)) return ret;

	std::ostringstream strb;
	strb << HIWORD(fileInf->dwFileVersionMS) << "."
		 << LOWORD(fileInf->dwFileVersionMS) << "."
		 << HIWORD(fileInf->dwFileVersionLS) << "."
		 << LOWORD(fileInf->dwFileVersionLS);
	return strb.str();
	}

#endif //WIN32

#if defined(linux) || defined(__APPLE__)
#include <dlfcn.h>
#include <sys/stat.h>

std::string DynamicLibrary::arrPaths[] = { "","/lib/","/usr/local/lib/","/usr/lib/"};

DynamicLibrary::DynamicLibrary(const char *dllName,const char *pathHint,
	int version) : name(dllName) {
	m_pathHint = pathHint;
	construct(version);
	}

#include <iostream>

void DynamicLibrary::construct(int version) {
	size_t i,j;
	std::ostringstream buf;
	buf << version;
	std::string arrStr[] = {
			name,
			name + ".so",
		"lib" + name + ".so",
			name + ".so." + buf.str(),
		"lib" + name + ".so." + buf.str(),
		},search,qname;
	mLibhandle = NULL;
	for(j = 0;j < sizeof(arrPaths) / sizeof(*arrPaths);j++) {
	for(i = 0;i < sizeof(arrStr) / sizeof(*arrStr);i++) {
		qname = arrPaths[j] + arrStr[i];

		search+= qname + ",";
		mLibhandle=dlopen(qname.c_str(),RTLD_LAZY);
		if (mLibhandle) break;

		qname = arrPaths[j] + m_pathHint + "/" + arrStr[i];
		search+= qname + ",";
		mLibhandle=dlopen(qname.c_str(),RTLD_LAZY);
		if (mLibhandle) break;
		}
		}
	if (!mLibhandle) {
		buf.str("");
		buf << "Dynamic library '" << name << "' not found in system";
		throw std::runtime_error(buf.str());
		}
	name = arrStr[i];
	}

DynamicLibrary::~DynamicLibrary() {
	}

DynamicLibrary::fProc DynamicLibrary::getProc(const char *procName) {
	std::ostringstream buf;
	void * ptr = dlsym(mLibhandle,procName);
	fProc proc = NULL;
	memcpy(&proc,&ptr,sizeof(ptr)); //hack around not being able to copy void to fn ptr
	if (dlerror() == 0)
		return proc;
	buf << "proc not found:" << procName;
	throw std::runtime_error(buf.str().c_str());
	}

void tryReadLink(std::string name,std::string path,std::string &result) {
	char buffer[1024];
	if (result.length() > 0) return;
	memset(buffer,0,sizeof(buffer));
	int link = readlink(std::string(path+name).c_str(),buffer,sizeof(buffer));
	if (-1!= link) {
		result = path + buffer;
		return;
		}
	struct stat buff;
	int file = stat(std::string(path+name).c_str(),&buff);
	if (-1!=file)
		result = path + name;
	}

//this is a hack, but should work most of the time. any way to ask dlopen for the actual file used ?
std::string DynamicLibrary::getVersionStr() {
	std::string result;
	for(size_t i = 0;i < sizeof(arrPaths) / sizeof(*arrPaths);i++) {
		tryReadLink(name,arrPaths[i],result);
		tryReadLink(name,arrPaths[i] + m_pathHint + "/",result);
		}
	if (result.length() == 0) result = "unknown";
	return result;
	}
#endif
