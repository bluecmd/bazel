@echo off
call C:\mxc\psecexe\env.cmd
set BB=C:\mxc\psecexe\tools\bash.exe
set SB=C:\mxc\psecexe\BazelSandbox.exe
set BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools
set BAZEL_MXC_DIR_GRANTS=1
cd /d C:\mxc\ob\zimdgeq3\execroot\_main
echo ===== 1 fastutil's grants, subshell
%SB% @C:\mxc\psecexe\fastutil.params -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
echo ===== 2 fastutil's grants, pipe and mktemp
%SB% @C:\mxc\psecexe\fastutil.params -- %BB% -c "echo a | tr a b; d=$(mktemp -d); echo d=$d; rm -rf $d"
echo rc=%ERRORLEVEL%
echo ===== 3 fastutil's grants, without DIR_GRANTS
set BAZEL_MXC_DIR_GRANTS=
%SB% @C:\mxc\psecexe\fastutil.params -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
set BAZEL_MXC_DIR_GRANTS=1
echo ===== 4 fastutil's grants, no TMPDIR
set BAZEL_PSEC_NO_TMPDIR=1
%SB% @C:\mxc\psecexe\fastutil.params -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
set BAZEL_PSEC_NO_TMPDIR=
echo ===== 5 only tools + cwd, from the execroot
%SB% -r C:\mxc\psecexe\tools -w C:\mxc\psecexe\t\out -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
echo ===== 6 fastutil's grants, nttest exec of busybox child
%SB% @C:\mxc\psecexe\fastutil.params -r C:\mxc\psecexe\nttest.exe -- C:\mxc\psecexe\nttest.exe exec %BB% -c "echo direct-child-ok"
