@echo off
cl /c sum.c
cl /c main.c
link /DYNAMICBASE:no main.obj sum.obj