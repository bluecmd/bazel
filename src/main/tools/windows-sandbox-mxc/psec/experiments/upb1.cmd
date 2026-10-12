@echo off
call C:\mxc\psecexe\env.cmd
set BB=C:\mxc\psecexe\tools\bash.exe
set SB=C:\mxc\psecexe\BazelSandbox.exe
set BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools
set BAZEL_MXC_DIR_GRANTS=1
cd /d C:\mxc\ob\zimdgeq3\execroot\_main
echo ===== 1 upb action's grants, dirname subshell
%SB% @C:\mxc\psecexe\upb.params -- %BB% -c "echo d=$(dirname external/protobuf+/src/google/protobuf/descriptor.proto)"
echo rc=%ERRORLEVEL%
echo ===== 2 upb action's grants, no DIR_GRANTS
set BAZEL_MXC_DIR_GRANTS=
%SB% @C:\mxc\psecexe\upb.params -- %BB% -c "echo d=$(dirname external/protobuf+/src/google/protobuf/descriptor.proto)"
echo rc=%ERRORLEVEL%
set BAZEL_MXC_DIR_GRANTS=1
echo ===== 3 upb grants, runfiles kept read-only
set BAZEL_PSEC_RUNFILES_RO=1
%SB% @C:\mxc\psecexe\upb.params -- %BB% -c "echo d=$(dirname external/protobuf+/src/google/protobuf/descriptor.proto)"
echo rc=%ERRORLEVEL%
set BAZEL_PSEC_RUNFILES_RO=
echo ===== 4 upb grants, debug policy, plain echo
%SB% -D @C:\mxc\psecexe\upb.params -- %BB% -c "echo plain" 2>&1 | findstr /v /c:"  enum"
echo ===== 5 upb grants, the real command
%SB% @C:\mxc\psecexe\upb.params -- %BB% -c "source external/bazel_tools/tools/genrule/genrule-setup.sh; bazel-out/default_host_platform-opt-exec/bin/external/protobuf+/src/google/protobuf/compiler/protoc_minimal.exe --plugin=protoc-gen-upb_minitable=bazel-out/default_host_platform-opt-exec/bin/external/protobuf+/upb_generator/minitable/protoc-gen-upb_minitable_stage0.exe -I$(dirname external/protobuf+/src/google/protobuf/descriptor.proto)/../.. --upb_minitable_out=bootstrap_stage=1:C:/mxc/psecexe/t/out google/protobuf/compiler/plugin.proto"
echo rc=%ERRORLEVEL%
