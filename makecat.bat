cd /d %~dp0
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
inf2cat /driver:"%cd%\DistDriver" /os:XP_X86,Server2003_X86,XP_X64,Server2003_X64,Vista_X86,Server2008_X86,Vista_X64,Server2008_X64,7_X86,7_X64,Server2008R2_X64,8_X86,8_X64,Server8_X64,6_3_X86,6_3_X64,Server6_3_X64,10_X86,10_X64,Server10_X64,Server10_ARM64,10_AU_X86,10_AU_X64,Server2016_X64,10_RS2_X86,10_RS2_X64,10_RS3_X86,10_RS3_X64,10_RS3_ARM64,10_RS4_X86,10_RS4_X64,10_RS4_ARM64,10_RS5_X86,10_RS5_X64,ServerRS5_X64,10_RS5_ARM64,ServerRS5_ARM64,10_19H1_X86,10_19H1_X64,10_19H1_ARM64,10_VB_X86,10_VB_X64,10_VB_ARM64
@echo please sign the cat file... & pause
pushd "%cd%\DistDriver"
..\cabarc -r -p N ..\drivers.cab *
popd
@pause
