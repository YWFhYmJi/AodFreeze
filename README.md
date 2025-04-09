# AodFreeze
傲盾还原v3.2 修改自 [傲盾还原 By dbgger@gmail.com](https://code.google.com/p/diskflt) \
支持Windows7及以上版本的32位、64位系统 \
支持FAT、NTFS文件系统 \
自动保护MBR、GPT的分区表（保护盘分区表无法修改） \
防Ring3的穿透还原行为（SCSI Passthrough、IOCTL修改分区表）
支持驱动白名单、黑名单拦截（支持临时解除或开启驱动拦截），支持解冻空间，支持保护没有盘符的盘 \
**注意：开启驱动白名单后所有保护盘上原有的驱动会自动允许加载，不保护系统盘时不要开启驱动白名单** \
修复了会导致NTFS文件系统损坏的BUG

## 更新日志

V3.1
- 初始版本

V3.2
- 修复了Windows Server 2025安装后蓝屏的问题
- 修改了内存使用的计算和分区信息的获取代码
- 添加了驱动白名单的限制。注意：驱动白名单在Windows Server 2025上有BUG（会拦截系统驱动），不要使用。
