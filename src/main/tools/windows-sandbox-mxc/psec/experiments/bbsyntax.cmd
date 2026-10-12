@echo off
set BB=C:\mxc\psecexe\tools\busybox64.exe
echo ===== busybox applets of interest
%BB% --list | findstr /x /i "bash sh cp dirname mktemp unzip zip find xargs touch chmod tr sed grep cat echo pwd rm mkdir"
echo ===== bash-isms used by the tree's genrules
%BB% bash -c "set -euo pipefail; [[ \"Add-Exports: x\" =~ ^Add-Exports: ]] && echo regex-ok"
echo rc=%ERRORLEVEL%
%BB% bash -c "set -euo pipefail; x='Add-Exports: a b'; echo ${x#Add-Exports: }; for v in $x; do echo v=$v; done"
echo rc=%ERRORLEVEL%
%BB% bash -c "set -euo pipefail; printf 'a\r\nb\n c\n' | tr -d '\r' | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n / /g'"
echo rc=%ERRORLEVEL%
%BB% bash -c "set -euo pipefail; d=$(mktemp -d); echo x > $d/f; find $d -type f -print0 | xargs -0 touch -t 198001010000.00; ls -l $d; rm -rf $d; echo `dirname src/main/starlark/builtins_bzl/BUILD`"
echo rc=%ERRORLEVEL%
%BB% bash -c "set -euo pipefail; cat /dev/null; echo to-null > /dev/null; echo devnull-ok"
echo rc=%ERRORLEVEL%
echo ===== the actual generate_jvm_module_options.sh under busybox bash (outside the sandbox)
cd /d C:\mxc\bazel-src
%BB% bash src/main/cpp/generate_jvm_module_options.sh C:\mxc\psecexe\tools\ProcessMonitor.zip C:\mxc\psecexe\t\out\jmo.h
echo rc=%ERRORLEVEL%
type C:\mxc\psecexe\t\out\jmo.h
echo ===== C:\mxc\zip.exe native?
C:\mxc\zip.exe -v | findstr /i "Info-ZIP compiled"
