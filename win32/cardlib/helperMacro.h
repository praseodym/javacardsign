#if !defined(_WINDEF_) && !defined(HELPERMACROS_H)
#define MAKEWORD(a, b)      ((word)(((byte)(((dword)(a)) & 0xff)) | ((word)((byte)(((dword)(b)) & 0xff))) << 8))
#define LOBYTE(w)           ((byte)(((dword)(w)) & 0xff))
#define HIBYTE(w)           ((byte)((((dword)(w)) >> 8) & 0xff))
#endif
#ifndef HELPERMACROS_H
#define HELPERMACROS_H
#define LENOF(a) (sizeof(a)/sizeof(*(a)))
#define MAKEVECTOR(a) ByteVec(a,a + LENOF(a) )
#endif
