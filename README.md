# DiscordMixer

DiscordMixer is a vibe coded windows application for persistent Discord audio volume control.

Discord exposes separate audio streams (app sounds and voice chat) through the Windows Volume Mixer but does not persist their levels properly. This app monitors these sessions via WASAPI and re-applies configured volumes automatically.

## Build

```
rc /fo build/app.res src/app.rc
cl /Zi /EHsc /Fo:build/ /Fd:build/ /Fe:build/DiscordMixer.exe src/main.cpp build/app.res Ole32.lib Uuid.lib Wbemuuid.lib OleAut32.lib User32.lib Shell32.lib Comctl32.lib Gdi32.lib
```

## License

[MIT](LICENSE)
