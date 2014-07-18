cl /c ldr_hide.c
cl /c msg.c

link /DLL msg.obj user32.lib

link /dynamicbase:no ldr_hide.obj msg.lib