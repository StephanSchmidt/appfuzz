# The terminal recording on appfuzz.dev and in the README.
# Render with bench/record.sh, which serves the demo apps locally and
# writes to its output directory (OUT).
Output OUT/demo.gif
Output OUT/demo.webm
Output OUT/demo.mp4

Set Shell bash
Set FontSize 15
Set Width 1280
Set Height 460
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set CursorBlink false

Hide
Type "source bench/record-env.sh && clear"
Enter
Show

Sleep 600ms
Type "appfuzz --human https://appfuzz.dev/demo/chatty.wasm"
Sleep 700ms
Enter
Wait+Screen@60s /Next/
Sleep 7s
