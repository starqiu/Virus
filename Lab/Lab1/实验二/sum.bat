@echo off
cl /c sum.c
link /DYNAMICBASE:no sum.obj
sum.exe