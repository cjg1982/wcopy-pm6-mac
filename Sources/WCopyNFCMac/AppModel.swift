import AppKit
import Combine
import Foundation

enum NavigationPage: String, CaseIterable, Identifiable {
    case overview = "概览"
    case read = "读取与备份"
    case directCopy = "读取与复制"
    case restore = "恢复转储"
    case mfocRecovery = "密钥恢复"
    case uid = "UID 工具"
    case format = "格式化"
    case libnfc = "libnfc 桥接"
    case diagnostics = "诊断"

    var id: String { rawValue }
    var icon: String {
        switch self {
        case .overview: return "square.grid.2x2"
        case .read: return "wave.3.right.circle"
        case .directCopy: return "doc.on.doc"
        case .restore: return "square.and.arrow.down.on.square"
        case .mfocRecovery: return "key.horizontal"
        case .uid: return "number.square"
        case .format: return "eraser"
        case .libnfc: return "point.3.connected.trianglepath.dotted"
        case .diagnostics: return "stethoscope"
        }
    }
}

enum ConnectionState: Equatable {
    case disconnected
    case connecting
    case connected
    case incompatible

    var title: String {
        switch self {
        case .disconnected: return "未连接"
        case .connecting: return "正在连接"
        case .connected: return "协议就绪"
        case .incompatible: return "协议未通过"
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published var page: NavigationPage = .overview
    @Published var devices: [HIDDeviceDescriptor] = []
    @Published var selectedDeviceID: UInt64?
    @Published var connectionState: ConnectionState = .disconnected
    @Published var firmware = "-"
    @Published var readerSerial = "-"
    @Published var sequence = "-"
    @Published var busy = false
    @Published var progress = 0.0
    @Published var operationText = ""
    @Published var operationCancellable = true
    @Published var logText = ""
    @Published var errorMessage: String?
    @Published var noticeMessage: String?
    @Published var readResult: ReadResult?
    @Published var activeDump: DumpDocument?
        @Published var importedDump: DumpDocument?
    @Published private(set) var copyCache: DumpDocument?
    @Published private(set) var copyCount = 0
    @Published private(set) var copyStatus = "请放入源卡，点击读取源卡"
    @Published var detectedSectorKeys: [Int: SectorKeyResult]?
    @Published var keyResults: [Int: SectorKeyResult] = [:]
    @Published var keyCheckAttempts = 0
    @Published var keyCandidateCount = 0
    @Published var showMfocPrompt = false
    @Published var rawResponse = ""

    private let operationQueue = DispatchQueue(label: "app.wcopy.nfc.operation", qos: .userInitiated)
    private var reader: WCopyReader?
    private var cancellationToken: CancellationToken?

    var selectedDevice: HIDDeviceDescriptor? {
        guard let selectedDeviceID else { return nil }
        return devices.first { $0.id == selectedDeviceID }
    }

    var canOperate: Bool { connectionState == .connected && !busy }

    func refreshDevices() {
        guard !busy else { return }
        let previous = selectedDeviceID
        devices = HIDDeviceScanner.scan()
        if let previous, devices.contains(where: { $0.id == previous }) {
            selectedDeviceID = previous
        } else {
            selectedDeviceID = devices.first?.id
            if connectionState == .connected { disconnect() }
        }
    }

    func connect() {
        guard !busy, let descriptor = selectedDevice else {
            errorMessage = AppError.noDevice.localizedDescription
            return
        }
        disconnect()
        let transport: HIDTransport
        do { transport = try HIDTransport(descriptor: descriptor) }
        catch { errorMessage = error.localizedDescription; return }

        let newReader = WCopyReader(transport: transport, productID: descriptor.productID, logger: appendLog)
        reader = newReader
        connectionState = .connecting
        startOperation(label: "连接读卡器", allowDisconnected: true) { [weak self] token in
            try newReader.sync(progress: { value in self?.updateProgress(value, text: "同步设备协议") }, token: token)
            let info = try newReader.initialize()
            Task { @MainActor [weak self] in
                self?.firmware = info.firmware
                self?.readerSerial = info.serial
                self?.sequence = String(format: "0x%04X", info.sequence)
                self?.connectionState = .connected
                self?.noticeMessage = descriptor.productID == 0xB008
                    ? "0416:B008 已通过 wCopy/PN532 协议握手"
                    : "读卡器已连接"
            }
        } failure: { [weak self] error in
            self?.reader?.close()
            self?.reader = nil
            self?.connectionState = .incompatible
            self?.errorMessage = error.localizedDescription
        }
    }

    func disconnect() {
        guard !busy else { return }
        cancellationToken?.cancel()
        reader?.close()
        reader = nil
        connectionState = .disconnected
        firmware = "-"
        readerSerial = "-"
        sequence = "-"
    }

    func cancelOperation() { cancellationToken?.cancel() }

    /// 「开始读取」：先用界面中填写的密钥直接读取；若认证失败或未填写密钥，
    /// 自动以该密钥 + 快速字典进行密钥检测并读取。
    func readAndDetect(
        key: String,
        keyType: KeyType,
        readAll: Bool,
        sectors: String,
        scanMode: CardScanMode,
        autoRecover: Bool = false,
        recoveryRounds: Int = 3
    ) {
        guard let reader else { errorMessage = AppError.notConnected.localizedDescription; return }
        if autoRecover {
            readAndRecover(key: key, readAll: readAll, sectors: sectors,
                           scanMode: scanMode, rounds: recoveryRounds)
            return
        }
        readResult = nil
        activeDump = nil
        startOperation(label: "自动检测并读取") { [weak self] token in
            guard let self else { return }
            let normalized = try? normalizeMifareKey(key)

            // Fast path: read directly with the user-supplied key.
            if let normalized {
                let requested = try (readAll ? nil : parseSectors(sectors))
                let fast = try reader.readCard(
                    keyHex: normalized,
                    keyType: keyType,
                    sectors: requested,
                    scanMode: scanMode,
                    progress: { value, text in self.updateProgress(value, text: text) },
                    token: token
                )
                if fast.failedSectors.isEmpty && !fast.blocks.isEmpty {
                    let dump = fast.dump(key: normalized, keyType: keyType)
                    let sectorCount = fast.target.kind.sectorCount
                    Task { @MainActor [weak self] in
                        guard let self else { return }
                        let authenticated = Set(0 ..< sectorCount).subtracting(fast.failedSectors)
                        for sector in authenticated {
                            var result = self.keyResults[sector] ?? SectorKeyResult(sector: sector)
                            if keyType == .a {
                                result.keyA = normalized
                            } else {
                                result.keyB = normalized
                                result.keyBAuthenticates = true
                            }
                            self.keyResults[sector] = result
                        }
                        self.readResult = fast
                        self.activeDump = dump
                        self.noticeMessage = "已用密钥 \(normalized) 读取 \(fast.blocks.count) 个块"
                    }
                    return
                }
                self.appendLog("密钥 \(normalized) 未能认证全部扇区，开始自动密钥检测")
            }

            // Detection path: only the user-supplied key (SAK 19 cards get the
            // UID-derived candidate added automatically inside checkKeys).
            var candidates: [String] = []
            if let normalized {
                candidates = [normalized]
            }
            let outcome = try reader.checkKeys(
                candidates: candidates,
                scanMode: scanMode,
                progress: { value, text in self.updateProgress(value, text: text) },
                token: token
            )
            let result = ReadResult(
                target: outcome.target,
                blocks: outcome.blocks,
                failedSectors: outcome.sectorKeys.values.filter { !$0.foundAny }.map(\.sector),
                failedBlocks: outcome.failedBlocks
            )
            let defaultAuthentication = outcome.sectorKeys.values.sorted { $0.sector < $1.sector }.compactMap { slot -> (String, KeyType)? in
                if let keyA = slot.keyA { return (keyA, .a) }
                if let keyB = slot.keyB, slot.keyBAuthenticates != false { return (keyB, .b) }
                return nil
            }.first
            let dump = defaultAuthentication.map {
                result.dump(key: $0.0, keyType: $0.1, sectorKeys: outcome.sectorKeys)
            }
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.keyResults = outcome.sectorKeys
                self.keyCheckAttempts = outcome.attempts
                self.keyCandidateCount = outcome.candidateCount
                self.readResult = result
                self.activeDump = dump
                let foundSlots = outcome.sectorKeys.values.reduce(0) { $0 + ($1.keyA == nil ? 0 : 1) + ($1.keyB == nil ? 0 : 1) }
                let totalSlots = outcome.sectorKeys.count * 2
                if foundSlots < totalSlots {
                    self.noticeMessage = nil
                    self.showMfocPrompt = true
                } else {
                    self.noticeMessage = "自动检测完成：\(outcome.attempts) 次认证，找到 \(foundSlots)/\(totalSlots) 个密钥槽"
                }
            }
        }
    }

    private func applyAutomaticRead(_ outcome: KeyCheckOutcome) {
        let sectors = outcome.sectorKeys.keys.sorted()
        let missing = AutomaticSectorRecovery.unresolvedSectors(sectors: sectors, blocks: outcome.blocks)
        let result = ReadResult(target: outcome.target, blocks: outcome.blocks,
                                failedSectors: missing, failedBlocks: outcome.failedBlocks)
        keyResults = outcome.sectorKeys
        keyCheckAttempts = outcome.attempts
        keyCandidateCount = outcome.candidateCount
        readResult = result
        let authentication: (String, KeyType)? = outcome.sectorKeys.values.sorted { $0.sector < $1.sector }.compactMap { item in
            if let a = item.keyA { return (a, KeyType.a) }
            if let b = item.keyB, item.keyBAuthenticates == true { return (b, KeyType.b) }
            return nil
        }.first
        activeDump = authentication.map { result.dump(key: $0.0, keyType: $0.1, sectorKeys: outcome.sectorKeys) }
    }

    private func readAndRecover(key: String, readAll: Bool, sectors: String,
                                scanMode: CardScanMode, rounds: Int) {
        guard let reader, canOperate else { return }
        let requested: [Int]?
        let candidates: [String]
        do {
            requested = try readAll ? nil : parseSectors(sectors)
            let supplied = key.trimmingCharacters(in: .whitespacesAndNewlines)
            candidates = MifareKeyDictionary.merged([supplied.isEmpty ? [] : [try normalizeMifareKey(supplied)],
                                                      MifareKeyDictionary.quickKeys])
        } catch { errorMessage = error.localizedDescription; return }
        keyResults = [:]
        readResult = nil
        activeDump = nil
        showMfocPrompt = false
        startOperation(label: "读取并自动补全未读扇区") { [weak self] token in
            guard let self else { return }
            let recovery = AutomaticSectorRecovery(reader: reader, logger: self.appendLog)
            let outcome = try recovery.run(candidates: candidates, sectors: requested, rounds: rounds,
                scanMode: scanMode, token: token,
                progress: { value, text in self.updateProgress(value, text: text) },
                checkpoint: { partial in
                    Task { @MainActor [weak self] in self?.applyAutomaticRead(partial) }
                })
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.applyAutomaticRead(outcome)
                let unresolved = AutomaticSectorRecovery.unresolvedSectors(
                    sectors: outcome.sectorKeys.keys.sorted(), blocks: outcome.blocks)
                self.noticeMessage = unresolved.isEmpty
                    ? "所选扇区已全部读出，共 \(outcome.blocks.count) 块；未写入卡片"
                    : "已保留 \(outcome.blocks.count) 块，仍未读出扇区：\(unresolved.map(String.init).joined(separator: ", "))；可导出部分备份"
            }
        }
    }

    func checkKeys(
        preset: KeyDictionaryPreset,
        customKeys: [String],
        sectors: [Int]? = nil,
        rounds: Int = 1,
        scanMode: CardScanMode
    ) {
        guard let reader else { errorMessage = AppError.notConnected.localizedDescription; return }
        let candidates = MifareKeyDictionary.merged([preset.keys, customKeys])
        let retainedUID = readResult?.target.uid
        let retainedResults = sectors == nil ? [:] : keyResults
        keyResults = retainedResults
        keyCheckAttempts = 0
        keyCandidateCount = candidates.count
        readResult = nil
        activeDump = nil
        startOperation(label: "检查常用密钥") { [weak self] token in
            let outcome = try reader.checkKeysWithRetries(
                candidates: candidates,
                sectors: sectors,
                rounds: rounds,
                scanMode: scanMode,
                progress: { value, text in self?.updateProgress(value, text: text) },
                token: token
            )
            let target = outcome.target
            let results = outcome.sectorKeys
            let readResult = ReadResult(
                target: target,
                blocks: outcome.blocks,
                failedSectors: results.values.filter { !$0.foundAny }.map(\.sector),
                failedBlocks: outcome.failedBlocks
            )
            let defaultAuth = results.values.sorted { $0.sector < $1.sector }.compactMap { result -> (String, KeyType)? in
                if let keyA = result.keyA { return (keyA, .a) }
                if let keyB = result.keyB, result.keyBAuthenticates != false { return (keyB, .b) }
                return nil
            }.first
            let dump = defaultAuth.map {
                readResult.dump(key: $0.0, keyType: $0.1, sectorKeys: results)
            }
            Task { @MainActor [weak self] in
                self?.keyResults = retainedUID == target.uid ? retainedResults.merging(results) { _, new in new } : results
                self?.keyCheckAttempts = outcome.attempts
                self?.keyCandidateCount = outcome.candidateCount
                self?.readResult = readResult
                self?.activeDump = dump
                let foundSlots = results.values.reduce(0) { $0 + ($1.keyA == nil ? 0 : 1) + ($1.keyB == nil ? 0 : 1) }
                let totalSlots = results.count * 2
                if foundSlots < totalSlots {
                    self?.noticeMessage = nil
                    self?.showMfocPrompt = true
                } else {
                    self?.noticeMessage = "完成 \(outcome.attempts) 次认证，找到 \(foundSlots)/\(totalSlots) 个密钥槽"
                }
            }
        }
    }

    func pasteSectorKey(_ clipboardValue: String, sector: Int, type: KeyType) {
        guard let reader else { errorMessage = AppError.notConnected.localizedDescription; return }
        let key: String
        do { key = try normalizeMifareKey(clipboardValue) }
        catch { errorMessage = AppError.invalidKey.localizedDescription; return }

        let currentResults = keyResults
        startOperation(label: "验证扇区 \(sector) Key \(type.rawValue)") { [weak self] token in
            guard let self else { return }
            guard let target = try reader.selectTarget() else { throw AppError.noCard }
            var result = currentResults[sector] ?? SectorKeyResult(sector: sector)
            if type == .b, result.keyBAuthenticates == false {
                throw AppError.operation("扇区 \(sector) 的 Key B 字段是 DATA，不能用于 Key B 认证")
            }
            guard try reader.verifySectorKey(
                keyHex: key,
                sector: sector,
                type: type,
                target: target,
                token: token
            ) else {
                throw AppError.operation("粘贴的密钥无法认证扇区 \(sector) Key \(type.rawValue)，未保存")
            }
            Task { @MainActor [weak self] in
                guard let self else { return }
                if type == .a {
                    result.keyA = key
                } else {
                    result.keyB = key
                    result.keyBAuthenticates = true
                }
                self.keyResults[sector] = result
                self.noticeMessage = "扇区 \(sector) Key \(type.rawValue) 已验证并保存"
            }
        }
    }

    func downloadDictionary(
        _ source: OnlineKeyDictionarySource,
        completion: @escaping (Result<DownloadedKeyDictionary, Error>) -> Void
    ) {
        guard !busy else { return }
        let request = URLRequest(url: source.url, cachePolicy: .reloadRevalidatingCacheData, timeoutInterval: 30)
        URLSession.shared.dataTask(with: request) { data, response, error in
            let result: Result<DownloadedKeyDictionary, Error>
            if let error {
                result = .failure(error)
            } else if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                result = .failure(AppError.operation("词典服务器返回 HTTP \(http.statusCode)"))
            } else if let data, let text = String(data: data, encoding: .utf8) {
                let parsed = MifareKeyDictionary.parse(text)
                result = .success(DownloadedKeyDictionary(source: source, text: text, parsed: parsed))
            } else {
                result = .failure(AppError.operation("下载内容不是有效 UTF-8 文本"))
            }
            Task { @MainActor in completion(result) }
        }.resume()
    }

    func readCopySource(key: String) {
        guard canOperate, let reader, copyCache == nil else { return }
        copyStatus = "正在读取源卡…"
        startOperation(label: "读取源卡到缓存") { [weak self] token in
            guard let self else { return }
            do {
                let custom = try normalizeMifareKey(key)
                let outcome = try reader.checkKeys(candidates: MifareKeyDictionary.merged([[custom], KeyDictionaryPreset.common.keys]),
                    progress: { self.updateProgress($0, text: $1) }, token: token)
                let missing = AutomaticSectorRecovery.unresolvedSectors(
                    sectors: Array(0..<outcome.target.kind.sectorCount), blocks: outcome.blocks)
                guard missing.isEmpty, !outcome.blocks.isEmpty else {
                    throw AppError.operation("源卡读取不完整，未读扇区：\(missing)。未建立复制缓存，请到读取与备份页面检查")
                }
                let result = ReadResult(target: outcome.target, blocks: outcome.blocks, failedSectors: [], failedBlocks: [])
                let dump = try result.dump(key: custom, keyType: .a, sectorKeys: outcome.sectorKeys).validated()
                Task { @MainActor [weak self] in
                    self?.copyCache = dump
                    self?.copyCount = 0
                    self?.copyStatus = "读取成功，已缓存 \(dump.blocks.count) 块。请取走源卡，放入空卡后点击复制"
                }
            } catch {
                Task { @MainActor [weak self] in self?.copyStatus = "读取失败，未建立缓存，请重新读取" }
                throw error
            }
        }
    }

    func copyCachedSource(mode: CardCopyMode, targetKey: String) {
        guard canOperate, let reader, let dump = copyCache else { return }
        copyStatus = "正在复制，请保持卡片不动…"
        startOperation(label: "复制缓存到当前卡", cancellable: false) { [weak self] token in
            guard let self else { return }
            do {
                try mode.validate(dump)
                let key = try normalizeMifareKey(targetKey)
                guard let target = try reader.selectTarget() else { throw AppError.noCard }
                guard HexCodec.string(target.uid) != dump.uid else {
                    throw AppError.operation("当前卡 UID 与源卡相同，请取走源卡并放入新的空卡")
                }
                let result = try reader.restore(dump: dump, options: RestoreOptions(
                    keyOverride: key, keyTypeOverride: .a,
                    includeBlock0: mode.includesProtectedBlocks, includeTrailers: mode.includesProtectedBlocks,
                    verify: true), progress: { self.updateProgress($0, text: $1) }, token: token)
                guard result.failed.isEmpty, result.verification?.passed == true else {
                    throw AppError.operation("复制或校验失败，失败块：\(result.failed)。缓存已保留，请检查当前卡；不会自动重写")
                }
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    self.copyCount += 1
                    self.copyStatus = "复制成功，写入并校验 \(result.written) 块。请放入下一张空卡继续复制，或点击结束"
                }
            } catch {
                Task { @MainActor [weak self] in self?.copyStatus = "复制未完成，源卡缓存仍保留。请查看错误信息" }
                throw error
            }
        }
    }

    func endCopySession() {
        guard !busy else { return }
        copyCache = nil
        copyCount = 0
        copyStatus = "本次复制已结束，缓存已清空。请放入新的源卡"
    }

    func restoreDump(options: RestoreOptions, scanMode: CardScanMode) {
        guard let reader else { errorMessage = AppError.notConnected.localizedDescription; return }
        guard let dump = importedDump else { errorMessage = "请先导入 JSON 或 MFD 转储"; return }
        startOperation(label: "恢复转储", cancellable: false) { [weak self] token in
            let result = try reader.restore(
                dump: dump,
                options: options,
                scanMode: scanMode,
                progress: { value, text in self?.updateProgress(value, text: text) },
                token: token
            )
            Task { @MainActor [weak self] in
                let detail: String
                if let report = result.verification {
                    detail = "重新认证校验：一致 \(report.matched)/\(report.checked) 块；差异 \(report.mismatchedBlocks)，无法读取 \(report.unreadableBlocks)，密钥异常扇区 \(report.failedKeySectors)"
                } else { detail = "未启用写后校验，仅收到设备写入应答" }
                if result.failed.isEmpty {
                    self?.noticeMessage = "设备接受写入 \(result.written) 块，跳过 \(result.skipped) 块。\(detail)"
                } else {
                    self?.errorMessage = "写入/校验未全部通过，失败块：\(result.failed)。\(detail)；请勿直接当作可用复制卡"
                }
            }
        }
    }

    func verifyImportedDump(options: RestoreOptions, scanMode: CardScanMode) {
        guard let reader, canOperate else { return }
        guard let dump = importedDump else { errorMessage = "请先导入要比较的源文件"; return }
        startOperation(label: "只读校验卡片", cancellable: true) { [weak self] token in
            let report = try reader.verifyDump(dump: dump, options: options, scanMode: scanMode,
                progress: { value, text in self?.updateProgress(value, text: text) }, token: token)
            Task { @MainActor [weak self] in
                let detail = "一致 \(report.matched)/\(report.checked) 块；差异块 \(report.mismatchedBlocks)，无法读取 \(report.unreadableBlocks)，密钥异常扇区 \(report.failedKeySectors)"
                if report.passed { self?.noticeMessage = "只读校验完成：\(detail)。仅确认内容一致，没有执行写入" }
                else { self?.errorMessage = "只读校验未通过：\(detail)" }
            }
        }
    }

    func detectTargetKeys(scanMode: CardScanMode, preset: KeyDictionaryPreset = .common, completion: @escaping ([Int: SectorKeyResult]) -> Void) {
        guard let reader else { errorMessage = AppError.notConnected.localizedDescription; completion([:]); return }
        startOperation(label: "检测目标卡密钥") { [weak self] token in
            let outcome = try reader.checkKeys(
                candidates: preset.keys,
                scanMode: scanMode,
                progress: { value, text in self?.updateProgress(value, text: text) },
                token: token
            )
            Task { @MainActor [weak self] in
                self?.detectedSectorKeys = outcome.sectorKeys
                self?.keyResults = outcome.sectorKeys
                completion(outcome.sectorKeys)
                let found = outcome.sectorKeys.values.reduce(0) { $0 + ($1.keyA == nil ? 0 : 1) + ($1.keyB == nil ? 0 : 1) }
                self?.noticeMessage = "检测到 \(found)/\(outcome.sectorKeys.count * 2) 个密钥槽"
            }
        }
    }

    func importSectorKeys(from url: URL) {
        do {
            let data = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            let raw = try decoder.decode([String: [String: String?]].self, from: data)
            var keys: [Int: SectorKeyResult] = [:]
            for (sectorStr, keyMap) in raw {
                guard let sector = Int(sectorStr), sector >= 0, sector < 64 else { continue }
                let keyA = keyMap["a"].flatMap { $0 }.flatMap { (try? HexCodec.data(from: $0, expectedBytes: 6)).map { HexCodec.string($0) } }
                let keyB = keyMap["b"].flatMap { $0 }.flatMap { (try? HexCodec.data(from: $0, expectedBytes: 6)).map { HexCodec.string($0) } }
                guard keyA != nil || keyB != nil else { continue }
                keys[sector] = SectorKeyResult(sector: sector, keyA: keyA, keyB: keyB, keyBAuthenticates: keyB != nil ? true : nil)
            }
            detectedSectorKeys = keys.isEmpty ? nil : keys
            keyResults = keys
            noticeMessage = keys.isEmpty ? "未从文件中读取到有效扇区密钥" : "已导入 \(keys.count) 个扇区的密钥"
        } catch {
            errorMessage = "扇区密钥文件解析失败：\(error.localizedDescription)"
        }
    }

    func goToMfocRecovery() {
        showMfocPrompt = false
        page = .mfocRecovery
    }

    func dismissMfocPrompt() {
        showMfocPrompt = false
    }

    func writeUID(uid: String, key: String) {
        guard let reader else { errorMessage = AppError.notConnected.localizedDescription; return }
        startOperation(label: "写入 UID", cancellable: false) { [weak self] token in
            let uidData: Data
            do { uidData = try HexCodec.data(from: uid, expectedBytes: 4) }
            catch { throw AppError.invalidUID }
            _ = try reader.writeUID(newUID: uidData, keyHex: key, token: token)
            Task { @MainActor [weak self] in self?.noticeMessage = "UID 已写入并通过回读验证" }
        }
    }

    func formatCard(
        key: String,
        keyType: KeyType,
        sectors: String,
        gpb: String,
        scanMode: CardScanMode
    ) {
        guard let reader else { errorMessage = AppError.notConnected.localizedDescription; return }
        startOperation(label: "格式化卡片", cancellable: false) { [weak self] token in
            let selectedSectors = try parseSectors(sectors)
            let gpbData = try HexCodec.data(from: gpb, expectedBytes: 1)
            let failed = try reader.format(
                keyHex: key,
                keyType: keyType,
                sectors: selectedSectors,
                gpb: gpbData[0],
                scanMode: scanMode,
                progress: { value, text in self?.updateProgress(value, text: text) },
                token: token
            )
            Task { @MainActor [weak self] in
                self?.noticeMessage = failed.isEmpty ? "卡片格式化完成，UID 块未改动" : "格式化结束，失败扇区：\(failed.map(String.init).joined(separator: ", "))"
            }
        }
    }

    func sendRawCommand(_ hex: String) {
        guard let reader else { errorMessage = AppError.notConnected.localizedDescription; return }
        startOperation(label: "发送 PN532 命令") { [weak self] _ in
            let command = try HexCodec.data(from: hex)
            let readOnlyCommands: Set<UInt8> = [0x02, 0x04, 0x06, 0x4A]
            guard command.count >= 2, command[0] == 0xD4, readOnlyCommands.contains(command[1]) else {
                throw AppError.operation("诊断页只允许 GetFirmwareVersion、GetGeneralStatus、ReadRegister 和 InListPassiveTarget 等只读命令")
            }
            let response = try reader.rawPN532(command)
            Task { @MainActor [weak self] in self?.rawResponse = HexCodec.string(response, separator: " ") }
        }
    }

    func runLibNFC(commandLine: String, statusCode: ((Int32) -> Void)? = nil, completion: ((Int32) -> Void)? = nil) {
        guard !commandLine.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            errorMessage = "请输入 libnfc 命令"
            return
        }
        guard !busy, connectionState == .connected, let reader else {
            errorMessage = AppError.notConnected.localizedDescription
            return
        }
        let executableURL = Bundle.main.executableURL
            ?? URL(fileURLWithPath: CommandLine.arguments[0])

        // The verified terminal flow starts with a fresh HID session. Release the
        // GUI session before launching this same executable in CLI mode.
        reader.close()
        self.reader = nil
        connectionState = .disconnected
        firmware = "-"
        readerSerial = "-"
        sequence = "-"

        startOperation(label: "libnfc 桥接", allowDisconnected: true) { [weak self] token in
            let status = try Self.runCLIBridge(
                executableURL: executableURL,
                commandLine: commandLine,
                logger: self?.appendLog ?? { _ in },
                token: token
            )
            Task { @MainActor [weak self] in
                self?.noticeMessage = "libnfc 命令结束，退出码 \(status)；读卡器已释放，请重新连接后继续操作"
                statusCode?(status)
                completion?(status)
            }
        }
    }

    func runNativeRecovery(probes: Int = 20, progress: ((Double, String) -> Void)? = nil) {
        guard connectionState == .connected, let reader else {
            errorMessage = AppError.notConnected.localizedDescription
            return
        }
        guard readResult != nil, !keyResults.isEmpty else {
            errorMessage = "请先运行密钥检查以获取已知密钥"
            return
        }
        let knownEntries = keyResults.values.sorted(by: { $0.sector < $1.sector })
        let exploitEntries: [(sector: Int, keyHex: String, type: KeyType)] = knownEntries.flatMap { result -> [(Int, String, KeyType)] in
            var entries: [(Int, String, KeyType)] = []
            if let keyA = result.keyA { entries.append((result.sector, keyA, .a)) }
            if let keyB = result.keyB, result.keyBAuthenticates != false { entries.append((result.sector, keyB, .b)) }
            return entries
        }
        guard !exploitEntries.isEmpty else {
            errorMessage = "没有可用的已知密钥作为攻击入口"
            return
        }
        let missingSlots = keyResults.values.flatMap { result -> [(Int, KeyType)] in
            var slots: [(Int, KeyType)] = []
            if result.keyA == nil { slots.append((result.sector, .a)) }
            if result.keyB == nil, result.keyBAuthenticates != false { slots.append((result.sector, .b)) }
            return slots
        }
        guard !missingSlots.isEmpty else {
            noticeMessage = "所有密钥槽已找到，无需恢复"
            return
        }

        let currentTarget = readResult!.target
        startOperation(label: "原生 Nested 密钥恢复", cancellable: true) { [weak self] token in
            guard let self else { return }

            let session = NestedRecoverySession(transport: reader, target: currentTarget, logger: self.appendLog)
            var recoveredCount = 0

            for (idx, slot) in missingSlots.enumerated() {
                try token.check()
                let slotProgress = Double(idx) / Double(missingSlots.count)
                self.updateProgress(slotProgress, text: "恢复扇区 \(slot.0) Key \(slot.1.rawValue)")

                var candidates: [String] = []
                var foundExploit = false
                for exploit in exploitEntries {
                    try token.check()
                    guard let exploitKeyData = try? HexCodec.data(from: exploit.keyHex, expectedBytes: 6) else { continue }
                    self.appendLog("尝试用扇区 \(exploit.sector) Key \(exploit.type.rawValue) = \(exploit.keyHex) 作为入口")
                    do {
                        candidates = try session.recoverKey(
                            exploitSector: exploit.sector,
                            exploitKey: exploitKeyData,
                            exploitType: exploit.type,
                            targetSector: slot.0,
                            targetType: slot.1,
                            probes: probes
                        ) { p, text in
                            let overall = slotProgress + p / Double(missingSlots.count)
                            self.updateProgress(overall, text: text)
                        }
                        if !candidates.isEmpty {
                            foundExploit = true
                            self.appendLog("使用扇区 \(exploit.sector) Key \(exploit.type.rawValue) 成功生成候选")
                            break
                        }
                    } catch {
                        self.appendLog("扇区 \(exploit.sector) Key \(exploit.type.rawValue) 失败：\(error.localizedDescription)")
                    }
                }
                guard foundExploit, !candidates.isEmpty else {
                    self.appendLog("扇区 \(slot.0) Key \(slot.1.rawValue)：所有入口均未能生成候选")
                    progress?(Double(idx + 1) / Double(missingSlots.count),
                              "扇区 \(slot.0) Key \(slot.1.rawValue)：未生成候选")
                    continue
                }

                var found = false
                for candidate in candidates.prefix(50) {
                    try token.check()
                    guard let keyBytes = try? HexCodec.data(from: candidate, expectedBytes: 6) else { continue }
                    let topBlock = CardLayout.firstBlock(of: slot.0)
                    if try reader.authenticate(
                        block: topBlock,
                        uid: currentTarget.uid,
                        key: keyBytes,
                        type: slot.1
                    ) {
                        self.appendLog("扇区 \(slot.0) Key \(slot.1.rawValue) = \(candidate)（已验证）")
                        let revealed = Self.revealKeyBIfMissing(
                            sector: slot.0,
                            keyHex: candidate,
                            target: currentTarget,
                            reader: reader
                        )
                        Task { @MainActor [weak self] in
                            guard let self else { return }
                            var result = self.keyResults[slot.0] ?? SectorKeyResult(sector: slot.0)
                            if slot.1 == .a {
                                result.keyA = candidate
                                if let revealed {
                                    result.keyB = revealed.keyB
                                    result.keyBAuthenticates = revealed.keyBAuthenticates
                                }
                            } else {
                                result.keyB = candidate
                                result.keyBAuthenticates = true
                            }
                            self.keyResults[slot.0] = result
                        }
                        if let revealed {
                            self.appendLog("扇区 \(slot.0) 尾块揭示 Key B 字段 = \(revealed.keyB)（\(revealed.keyBAuthenticates == true ? "可认证" : "DATA")）")
                        }
                        recoveredCount += 1
                        found = true
                        break
                    }
                }
                if !found {
                    self.appendLog("扇区 \(slot.0) Key \(slot.1.rawValue)：候选密钥均未通过实卡认证")
                }
            }

            let totalMissing = missingSlots.count
            self.updateProgress(1, text: "恢复完成")
            Task { @MainActor [weak self] in
                self?.noticeMessage = "原生 Nested 恢复完成：\(recoveredCount)/\(totalMissing) 个缺失密钥槽"
                progress?(1, "恢复完成：\(recoveredCount)/\(totalMissing)")
            }
        }
    }

    private struct RevealedKeyB {
        let keyB: String
        let keyBAuthenticates: Bool?
    }

    /// When a sector's Key A becomes known and Key B is still missing, read the
    /// trailer with Key A to reveal the Key B field and test whether it can
    /// authenticate. Runs off the main actor.
    nonisolated private static func revealKeyBIfMissing(
        sector: Int,
        keyHex: String,
        target: CardTarget,
        reader: WCopyReader
    ) -> RevealedKeyB? {
        let trailer = CardLayout.trailerBlock(of: sector)
        guard let keyData = try? HexCodec.data(from: keyHex, expectedBytes: 6),
              (try? reader.authenticate(block: trailer, uid: target.uid, key: keyData, type: .a)) == true,
              let trailerData = try? reader.readBlock(trailer) else {
            return nil
        }
        let revealedKeyB = HexCodec.string(trailerData.suffix(6))
        let keyBData = try? HexCodec.data(from: revealedKeyB, expectedBytes: 6)
        let authenticates = keyBData.map { (try? reader.authenticate(block: trailer, uid: target.uid, key: $0, type: .b)) ?? false } ?? false
        return RevealedKeyB(keyB: revealedKeyB, keyBAuthenticates: authenticates)
    }

    nonisolated private static func runCLIBridge(
        executableURL: URL,
        commandLine: String,
        logger: @escaping (String) -> Void,
        token: CancellationToken
    ) throws -> Int32 {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = ["cli", "bridge", "--command", commandLine, "--verbose"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            throw AppError.operation("无法启动 CLI 桥接：\(error.localizedDescription)")
        }
        try? pipe.fileHandleForWriting.close()

        let outputQueue = DispatchQueue(label: "app.wcopy.nfc.cli-output")
        let outputGroup = DispatchGroup()
        var output = Data()
        outputGroup.enter()
        outputQueue.async {
            defer { outputGroup.leave() }
            var lineBuffer = ""
            var displayBuffer = ""
            var hiddenProtocolLines = 0
            var lastDisplayUpdate = Date()
            while let chunk = try? pipe.fileHandleForReading.read(upToCount: 4096),
                  !chunk.isEmpty {
                output.append(chunk)
                lineBuffer += String(decoding: chunk, as: UTF8.self)
                let lines = lineBuffer.components(separatedBy: "\n")
                lineBuffer = lines.last ?? ""
                for line in lines.dropLast() {
                    let cleaned = line.trimmingCharacters(in: .newlines)
                    guard !cleaned.isEmpty else { continue }
                    if shouldDisplayCLIBridgeLogLine(cleaned) {
                        displayBuffer += cleaned + "\n"
                    } else {
                        hiddenProtocolLines += 1
                    }
                }
                if displayBuffer.utf8.count >= 16_384
                    || Date().timeIntervalSince(lastDisplayUpdate) >= 0.25 {
                    logger(displayBuffer.trimmingCharacters(in: .newlines))
                    displayBuffer = ""
                    lastDisplayUpdate = Date()
                }
            }
            let finalLine = lineBuffer.trimmingCharacters(in: .newlines)
            if !finalLine.isEmpty {
                if shouldDisplayCLIBridgeLogLine(finalLine) {
                    displayBuffer += finalLine + "\n"
                } else {
                    hiddenProtocolLines += 1
                }
            }
            if hiddenProtocolLines > 0 {
                displayBuffer += "GUI 已隐藏 \(hiddenProtocolLines) 条高频 PN532 帧明细；完整协议仍由 CLI 正常处理。\n"
            }
            let finalDisplay = displayBuffer.trimmingCharacters(in: .newlines)
            if !finalDisplay.isEmpty {
                logger(finalDisplay)
            }
        }

        while process.isRunning {
            do {
                try token.check()
            } catch {
                process.terminate()
                process.waitUntilExit()
                outputGroup.wait()
                throw error
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        process.waitUntilExit()
        outputGroup.wait()

        return bridgeExitCode(from: output) ?? process.terminationStatus
    }

    nonisolated static func bridgeExitCode(from output: Data) -> Int32? {
        let lines = String(decoding: output, as: UTF8.self).split(separator: "\n").reversed()
        for line in lines {
            guard let data = String(line).data(using: .utf8),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  object["command"] as? String == "bridge",
                  let payload = object["data"] as? [String: Any],
                  let exitCode = payload["exitCode"] as? NSNumber else {
                continue
            }
            return exitCode.int32Value
        }
        return nil
    }

    nonisolated static func shouldDisplayCLIBridgeLogLine(_ line: String) -> Bool {
        let highFrequencyDetails = [
            "[wcopy-nfc] BRIDGE READ ",
            "[wcopy-nfc] libnfc InListPassiveTarget raw response",
            "[wcopy-nfc] libnfc 兼容：仅向旧工具将 SAK 19"
        ]
        return !highFrequencyDetails.contains { line.contains($0) }
    }

    func importDump(from url: URL) {
        guard !busy else { return }
        do {
            let data = try Data(contentsOf: url)
            let dump = url.pathExtension.lowercased() == "mfd"
                ? try DumpDocument.fromMFD(data)
                : try DumpDocument.fromJSON(data)
            importedDump = dump
            noticeMessage = "已导入 \(dump.blocks.count) 个块"
        } catch {
            importedDump = nil
            errorMessage = error.localizedDescription
        }
    }

    func exportActiveDump(to url: URL, mfd: Bool) {
        guard let dump = activeDump else { errorMessage = "当前没有可导出的读取结果"; return }
        do {
            let data = mfd ? try dump.mfdData() : try dump.jsonData()
            try data.write(to: url, options: .atomic)
            noticeMessage = "转储已保存到 \(url.lastPathComponent)"
        } catch { errorMessage = error.localizedDescription }
    }

    func diagnosticsText() -> String {
        let device = selectedDevice
        return """
        wCopy NFC for Mac diagnostics
        macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)
        Device: \(device?.productName ?? "not found")
        USB ID: \(device?.usbID ?? "-")
        HID usage: \(String(format: "%04X:%04X", device?.usagePage ?? 0, device?.usage ?? 0))
        Reports: IN \(device?.maxInputReportSize ?? 0) / OUT \(device?.maxOutputReportSize ?? 0)
        Connection: \(connectionState.title)
        Firmware: \(firmware)
        Reader serial: \(readerSerial)
        Sequence: \(sequence)

        \(logText)
        """
    }

    func clearLog() { logText = "" }

    nonisolated private func appendLog(_ message: String) {
        guard !message.isEmpty else { return }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let stamp = Date.now.formatted(date: .omitted, time: .standard)
            let updated = self.logText + "[\(stamp)] \(message)\n"
            if updated.count > 100_000 {
                self.logText = "[较早日志已截断]\n" + String(updated.suffix(80_000))
            } else {
                self.logText = updated
            }
        }
    }

    nonisolated private func updateProgress(_ value: Double, text: String) {
        Task { @MainActor [weak self] in
            self?.progress = min(max(value, 0), 1)
            self?.operationText = text
        }
    }

    private func startOperation(
        label: String,
        allowDisconnected: Bool = false,
        cancellable: Bool = true,
        work: @escaping (CancellationToken) throws -> Void,
        failure: ((Error) -> Void)? = nil
    ) {
        guard !busy else { return }
        if !allowDisconnected && connectionState != .connected {
            errorMessage = AppError.notConnected.localizedDescription
            return
        }
        let token = CancellationToken()
        cancellationToken = token
        busy = true
        operationCancellable = cancellable
        progress = 0
        operationText = label
        appendLog("开始：\(label)")
        operationQueue.async { [weak self] in
            do {
                try work(token)
                Task { @MainActor [weak self] in
                    self?.finishOperation()
                }
            } catch {
                Task { @MainActor [weak self] in
                    if let failure { failure(error) }
                    else if case AppError.cancelled = error { self?.noticeMessage = "操作已取消" }
                    else { self?.errorMessage = error.localizedDescription }
                    if case AppError.transport = error {
                        self?.reader?.close()
                        self?.reader = nil
                        self?.connectionState = .disconnected
                        self?.firmware = "-"
                        self?.readerSerial = "-"
                        self?.sequence = "-"
                    } else if error is MutationError {
                        self?.reader?.close()
                        self?.reader = nil
                        self?.connectionState = .disconnected
                        self?.firmware = "-"
                        self?.readerSerial = "-"
                        self?.sequence = "-"
                    }
                    self?.appendLog("失败：\(error.localizedDescription)")
                    self?.finishOperation()
                }
            }
        }
    }

    private func finishOperation() {
        busy = false
        progress = 0
        operationText = ""
        operationCancellable = true
        cancellationToken = nil
        if let reader { sequence = String(format: "0x%04X", reader.sequence ?? 0) }
    }

    private func rebuildActiveDumpFromKeyResults() {
        guard let readResult else { return }
        let authentication = keyResults.values.sorted { $0.sector < $1.sector }.compactMap { result -> (String, KeyType)? in
            if let keyA = result.keyA { return (keyA, .a) }
            if let keyB = result.keyB, result.keyBAuthenticates != false { return (keyB, .b) }
            return nil
        }.first
        activeDump = authentication.map {
            readResult.dump(key: $0.0, keyType: $0.1, sectorKeys: keyResults)
        }
    }
}
