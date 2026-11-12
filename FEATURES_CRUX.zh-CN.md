# Xiaomi Mi 9 Pro 5G（crux）功能与测试状态

适用源码版本：`0.4.5`
测试系统：`V13.0.1.0.RFXCNXM`（Android 11）
设备形态：单槽、非 A/B，无 `init_boot`，无 `super`

`0.4.5` 新增危险操作前的备份与责任声明。相关提示已在 `0.4.5` Recovery
真机中目视确认。下表的硬件功能结果来自上一版 `0.4.4`；除提示与 CI 修复
外，`0.4.5` 的功能行为没有变化。

本分支仅用于兴趣研究和设备测试，不保证稳定、持续维护或后续更新。详见
[FORK_NOTICE.md](FORK_NOTICE.md) 与 [DISCLAIMER.md](DISCLAIMER.md)。

执行任何会修改分区的操作前，必须先备份并验证所有可能被写入的分区。作者
及贡献者不对数据丢失、设备损坏或其他损失承担责任。

## 状态说明

- **已真机验证**：在当前 crux 上实际执行成功。
- **已实现待验收**：代码、编译和单元测试已完成，但缺少完整真机流程。
- **部分支持**：存在格式、硬件或功能边界。
- **不支持 / 不适用**：当前架构不提供，或设备形态不具备所需分区。

## 已真机验证

| 功能 | 验证结果 |
| --- | --- |
| Recovery 刷入与启动 | 已多次刷入 `recovery` 并正常启动 |
| 屏幕、触摸、电源/音量键 | Recovery 页面可正常操作 |
| Android 11 FBE 解密 | 使用机主锁屏凭据打开 `/data` 和 `/sdcard` |
| Keymaster 4.0 / Gatekeeper 1.0 | 共享 key、DE/0、CE/0 和用户凭据链路已验证 |
| WLAN 驱动与服务链 | IPA、qca、`wlan0`、supplicant 正常启动 |
| WLAN 连接 | 扫描、SAE 连接、DHCP 和互联网探测成功 |
| 文件管理、终端、挂载 | 固定分区读取和常规文件操作可用 |
| 应用缓存 + 系统缓存 | 两项同时清理成功；未解密的应用双开用户不阻塞 |
| data 文件系统修复 | 真机修复成功，device-mapper 清理错误不再出现 |
| 小分区备份与恢复 | 选择单个较小分区完成备份和恢复 |
| 设置持久化 | 深浅色、亮度、振动等跨 Recovery 重启保留 |
| WLAN 设置持久化 | WLAN 开关、已保存网络和凭据跨 Recovery 重启保留 |
| U 盘读取 | U 盘可正常挂载并读取 |
| AW8697 振动 | 点击和熄屏双振探针成功播放 |
| MIUI 在线更新检查 | 已获得最新版本、包大小和镜像地址 |
| 固定 `recovery` 镜像刷入 | fastboot 写入、回读和启动成功 |
| EDL | 页面直接进入失败；`fastboot oem edl` 可成功进入 9008 |

## 已实现待真机验收

| 功能 | 状态 |
| --- | --- |
| 安装页刷 `boot` / `dtbo` / `vbmeta` | 分区选择和写读校验已实现，尚未实际刷写 |
| SELinux relabel | 已支持固定分区规则，尚未真机执行 |
| 脚本 ZIP / `adb sideload` | 非 A/B 脚本路径已实现，尚未完成端到端安装 |
| MIUI 完整包下载与安装 | 检查和下载链路存在；2.7G 包最终安装尚未验收 |
| 未解锁双开用户的应用数据 | 可按加密目录名清除，相关单元测试通过，尚未真机执行 |
| 文件传输 / MTP | 代码和 USB 服务存在，尚未完成电脑端文件传输测试 |
| fastbootd | 已实现，尚未完成 fastbootd ↔ Recovery 往返 |
| 重启到 Bootloader / fastbootd | 相关页面存在，未逐项完成页面验收 |

## 部分支持

| 功能 | 限制 |
| --- | --- |
| 全量备份与恢复 | 小分区已通过；完整 data、全部系统分区和 IMEI/EFS 尚未整套验收 |
| U 盘 | 读取已验证；写入和异常拔插尚未验收 |
| MIUI 完整更新包 | 可检查版本；A/B `payload.bin` 包不适用于 crux，只可能支持固定分区脚本包 |
| Skyward 在线自更新 | 当前在线更新逻辑按 A/B recovery 分区设计，crux 未提供自更新页面 |
| 系统更新后自动重刷 Skyward | 当前按 A/B recovery 分区设计，crux 未启用 |
| EDL | 系统内 `reboot edl` 被平台降级为普通重启；需先进入 bootloader，再由电脑执行 `fastboot oem edl` |
| `init_boot` / `vendor_boot` 镜像 | crux 没有 `init_boot`；其他分区只按实际存在情况提供 |

## 不支持 / 不适用

| 功能 | 原因 |
| --- | --- |
| 双系统 | 当前双系统实现依赖 A/B `boot`、`init_boot` 和每槽 recovery；crux 不具备 |
| A/B 启动槽位切换 | crux 没有槽位 |
| 虚拟 A/B 快照合并 | crux 没有虚拟 A/B metadata/super |
| A/B `payload.bin` OTA | 设备为非 A/B |
| 按槽位在线更新 Skyward | crux 只有单个 recovery |
| 系统更新后按槽位自动恢复 Skyward | 同上 |

## 发布边界

- 不提交完整分区、`persist`、`keymaster`、`keystore`、IMEI 或设备序列号。
- 不提交 WLAN 密码、私钥、签名密钥和包含个人数据的日志。
- 不提交原厂完整固件、厂商二进制或未脱敏的测试交接记录。
- 发布二进制时提供对应 Git tag 的完整源码，并继续遵守
  `GPL-3.0-or-later`。
