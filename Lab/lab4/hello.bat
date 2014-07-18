cl /c hello.c
link hello.obj user32.lib
editbin /REBASE:BASE=0x00400000 hello.exe