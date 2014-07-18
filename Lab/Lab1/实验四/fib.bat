@echo off
cl /c add.c
cl /c fib.c
link /dll add.obj
link /dll fib.obj add.obj
cl /c main.c
link main.obj