Prebuilt driver has been created for Windows 10 1909 18363.

To use it for different versions, the offsets in DriverKit.c must be adjusted.


Activate testsigning and load the driver e.g. like this:

    sc create maldriver binPath= c:\users\user\DriverKit.sys type= kernel
    sc start maldriver

Then start the user\_space\_tool.

Prebuilt binaries are in the x64/Release folders.
