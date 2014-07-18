@echo off
rem generate hello.obj
cl /c hello.c
rem generate myprint.obj
cl /c myprint.c
rem generate hello.exe
link hello.obj myprint.obj
@echo the  running result is :
rem run hello.exe
hello.exe
pause