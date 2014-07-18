@echo off
cl /c add.c
link /DYNAMICBASE:no add.obj
add.exe