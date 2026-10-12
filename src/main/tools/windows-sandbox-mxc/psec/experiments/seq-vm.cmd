@echo off
rem seq-vm.cmd: tests (BazelSandbox2.exe) then the all-sandboxed busybox build (exe5), in the interactive session.
call C:\mxc\psecexe\tests.cmd
call C:\mxc\psecexe\bb-exe5.cmd
