cd /d %~dp0
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
inf2cat /driver:"%cd%\DistDriver" /os:Vista_X64
@echo please sign the cat file... & pause
pushd "%cd%\DistDriver"
..\cabarc -r -p N ..\drivers.cab *
popd
@pause
