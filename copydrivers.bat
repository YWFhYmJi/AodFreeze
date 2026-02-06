cd /d %~dp0
copy /y Release\diskflt.sys DistDriver\i386\
copy /y x64\Release\diskflt.sys DistDriver\amd64\
copy /y ARM64\Release\diskflt.sys DistDriver\arm64\
@pause
