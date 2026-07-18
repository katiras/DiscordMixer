#ifndef DISCORDMIXER_VERSION_H
#define DISCORDMIXER_VERSION_H

// ===========================================================
//  Bump the app version by editing these three numbers only.
// ===========================================================
#define APP_VER_MAJOR 1
#define APP_VER_MINOR 3
#define APP_VER_PATCH 0

// ---- Derived below; nothing to edit here. -----------------
// Stringize (two-step so the argument is expanded before it is quoted).
#define VER_STR_(x)  #x
#define VER_STR(x)   VER_STR_(x)
// Widen a string literal by pasting the L prefix; the rest of the
// concatenation is promoted to wide by the compiler.
#define VER_WIDE_(x) L##x
#define VER_WIDE(x)  VER_WIDE_(x)

// 0,0,0,0   -> FILEVERSION / PRODUCTVERSION (app.rc)
#define APP_VER_NUM  APP_VER_MAJOR,APP_VER_MINOR,APP_VER_PATCH,0
// "0.0.0"   -> narrow version string (app.rc string values)
#define APP_VER_STR  VER_STR(APP_VER_MAJOR) "." VER_STR(APP_VER_MINOR) "." VER_STR(APP_VER_PATCH)
// L"0.0.0"  -> wide version string (main.cpp prepends the "v")
#define APP_VER_WSTR VER_WIDE(APP_VER_STR)

#endif // DISCORDMIXER_VERSION_H
