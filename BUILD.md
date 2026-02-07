# 编译指南

## 1. 环境准备
安装以下编译工具：
- WDK 10.0.19041.5738
- Visual Studio 2019
  - Windows 10 SDK 10.0.19041.0
  - MSVC v142 - VS 2019 C++ x64/x86 build tools
  - MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (Latest)
  - C++ MFC for latest v142 build tools (x86 & x64)
  - C++ MFC for latest v142 build tools with Spectre Mitigations (x86 & x64)
  - C++ Windows XP Support for VS 2017 (v141) tools
  - 可选 ARM64 组件：MSVC v142 - VS 2019 C++ ARM64 build tools
  - 可选 ARM64 组件：MSVC v142 - VS 2019 C++ ARM64 Spectre-mitigated libs (Latest)
  - 可选 ARM64 组件：C++ MFC for latest v142 build tools (ARM64)
  - 可选 ARM64 组件：C++ MFC for latest v142 build tools with Spectre Mitigations (ARM64)

## 2. 编译
打开 `DiskFilter.sln`，按以下步骤编译：
1. 编译 `DiskFilter` x86+x64 (可选编译 ARM64)
2. 运行 `copydrivers.bat`
3. 对 `DistDriver\i386\diskflt.sys` 和 `DistDriver\amd64\diskflt.sys` 签名 (可选签名 ARM64)
4. 编译 `DiskfltInst`、`diskfltmgmt`、`DiskfltBufmon` x86+x64 (可选编译 ARM64)

### 常见编译错误解决方法
编译 `DiskFilter` 驱动时如果遇到 `wchar.h:642` 报错，则是 WDK 的问题，需要自行修改 `wchar.h`
```diff
642c642
< __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1(errno_t, _cgetws_s, _Post_readable_size_(*_Size) wchar_t, _Buffer, size_t *, _Size)
---
> __DEFINE_CPP_OVERLOAD_SECURE_FUNC_0_1(errno_t, _cgetws_s, _Post_readable_size_(*_Size) wchar_t, _Buffer, size_t *, _SizeRead)
```

## 3. 测试
建议在虚拟机中进行测试，测试前关闭Bitlocker、安全启动、所有杀毒软件、任何能阻止驱动安装的软件，如果没有正式驱动签名需要开启测试模式

### 测试失败处理方法
进入Windows PE，将系统盘挂载为C:，先运行 `chkdsk.exe /f C:` 修复文件系统，再运行 `diskfltmgmt.exe --password none uninstall --offline-directory C:\Windows` 进行卸载
