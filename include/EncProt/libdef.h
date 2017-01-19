#ifndef LIBDEF_H
#define LIBDEF_H

#ifdef _WIN32
#ifdef BUILD_DLL
#define DLL __declspec(dllexport)
#else
#define DLL __declspec(dllimport)
#endif
#else
#define DLL
#endif

#endif // LIBDEF_H
