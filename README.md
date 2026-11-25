# frida-detection

Tools and notes for spotting Frida on Android (arm64).

Right now there is one folder:

- `stalker/` — how to tell whether the thread you are on is being followed,
  plus the false starts I hit while checking it.

More detection work goes in its own folder as I get to it, so nothing here
should need renaming later. Everything is plain C unless stated otherwise, and
only the out-of-process reader needs root.
