# 来源与改动记录 / Provenance

核对日期 / Checked: 2026-10-20

## 直接上游 / Direct upstream

本地 PM6 改进版基于 [zhjcreator/wcopy-nfc-mac](https://github.com/zhjcreator/wcopy-nfc-mac)，起点为提交 [`9adcfbfdb3b3caafb26cc6f76aef32eb823302fd`](https://github.com/zhjcreator/wcopy-nfc-mac/commit/9adcfbfdb3b3caafb26cc6f76aef32eb823302fd)。上游采用 MIT；保留其 LICENSE、版权声明和 Git 历史。现有 SwiftUI 界面、CLI、IOKit 通信框架、Crypto1 和基础 Nested 恢复代码均来自该上游，不属于本次适配从零编写的内容。

This PM6 adaptation starts from the commit above. Existing GUI, CLI, IOKit transport, Crypto1 and baseline Nested recovery were inherited from the MIT-licensed macOS upstream. Original notices and history are retained.

## 协议来源 / Protocol lineage

[原 Linux 项目](https://github.com/mariogiordano96/wcopy-nfc-linux)，作者 Mario Giordano，MIT：USB-HID 帧、校验、同步、初始化和 PN532 封装的来源。完整许可保留于 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

## 本次本地改动 / Local changes

维护者组织需求及实机测试，使用 OpenAI Codex 辅助编写、修改代码和文档。未以此声称全部代码为原创。

- `HIDTransport.swift`、`WCopyReader.swift`：PM6 `0416:B029` 发现，V701A2 响应帧规则及精确认证拒绝响应兼容。
- `LibNFCBridge.swift`：针对实测固件的认证响应转换，保留其他响应的严格检查。
- `NestedRecovery.swift`：跳过该固件重复 SAM 初始化；变化认证序列、已知密钥对照采样、候选交集及实卡认证。
- `AutomaticSectorRecovery.swift`、`AppModel.swift`、`Views.swift`：仅补读未读扇区、有限轮数、取消、部分检查点、逐块重建认证。
- `CLI.swift`、测试和文档：扇区筛选、有限重试、兼容检查及使用说明。

这些是本次适配的改动范围；算法基础与原有代码的署名仍归原作者。只在特定固件和少量授权卡片上验证，不保证所有卡片恢复成功，也不是读卡器或门锁厂商的官方软件。

## 参考资料与外部工具 / References and external tools

| 来源 | 用途与分发状态 | 许可状态 |
| --- | --- | --- |
| [skylandersNFC/wCopy](https://github.com/skylandersNFC/wCopy) | Windows 编译版及本地协议排查参考；未随本项目分发其程序、资源或反汇编文件 | 其 README 明确没有源码；未据此取得代码再分发许可 |
| [nfc-tools/mfoc](https://github.com/nfc-tools/mfoc) / crapto1 | 上游 Crypto1/Nested 行为参考及本地对照测试；外部命令可选 | GPL-2.0，具体以其文件声明为准 |
| [nfc-tools/mfoc-hardnested](https://github.com/nfc-tools/mfoc-hardnested) | 本地诊断试验；不作为内置引擎，不分发其源码或二进制 | 以该项目和各文件许可为准 |
| [libnfc](https://github.com/nfc-tools/libnfc) / mfcuk | 可选外部工具，非 Swift 包依赖，不打包进应用 | 各工具单独适用其上游许可 |
| [Proxmark3](https://github.com/RfidResearchGroup/proxmark3) / [MIFARE Classic Tool](https://github.com/ikarus23/MifareClassicTool) | 用户选择后在线下载词典；不把下载词典提交进仓库或应用包 | 各词典遵循来源项目及文件许可 |

### 原生算法的许可核查边界

上游 THIRD_PARTY_NOTICES 声称 Crypto1/Nested 为独立实现。本次能确认这些文件继承自上述 macOS 提交，并对其作了修改；无法仅凭声明证明实现过程独立，尚未完成对 GPL 参考实现的逐段来源审计。保留上游 MIT 文件不代表对算法部分作出无争议许可保证。如发现包含或翻译 GPL 代码，发布前须依实际来源补充版权、许可和相应源码义务；不能用致谢代替许可。这里不擅自更改上游作者的许可证。

The upstream claims independent implementation. This adaptation records that claim as unverified provenance, not a completed license audit. Inherited MIT notices alone do not establish that GPL reference-code obligations are absent. Resolve any copied/translated code provenance before public distribution.

## 私有测试数据 / Private test material

`backups/`、`diagnostics/`、本地词典和通信记录仅供本机调试，不用于发布。公开测试使用合成 UID、密钥和数据。`.gitignore` 仅防止意外新增，不能删除已经存在于提交历史中的数据；发布前仍需检查待发布文件和历史。私有仓库存档不代表已完成公开发布所需的来源审计。
