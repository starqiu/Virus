cl /c msg.c
link /dll msg.obj
editbin /rebase:base=0x20000000 msg.dll
rem output headers to see if image base has been changed
dumpbin /headers msg.dll
cl /c hello.c
link hello.obj msg.lib
editbin /rebase:base=0x00400000 hello.exe
rem output headers to see if image base has been changed
dumpbin /headers hello.exe
hello.exe