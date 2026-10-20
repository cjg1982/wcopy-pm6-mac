import Foundation

/// Reads and authenticates only. Recovered keys are never written to a card.
final class AutomaticSectorRecovery {
    private let reader: WCopyReader
    private let logger: (String) -> Void

    init(reader: WCopyReader, logger: @escaping (String) -> Void) {
        self.reader = reader
        self.logger = logger
    }

    static func unresolvedSectors(sectors: [Int], blocks: [Int: Data]) -> [Int] {
        sectors.filter { sector in
            let first = CardLayout.firstBlock(of: sector)
            return (first..<(first + CardLayout.blockCount(in: sector))).contains { blocks[$0] == nil }
        }
    }

    func run(candidates: [String], sectors requested: [Int]?, rounds: Int,
             scanMode: CardScanMode, token: CancellationToken,
             progress: @escaping (Double, String) -> Void,
             checkpoint: @escaping (KeyCheckOutcome) -> Void) throws -> KeyCheckOutcome {
        guard (1...10).contains(rounds) else { throw AppError.operation("自动恢复轮数必须为 1–10") }
        guard let original = try reader.selectTarget() else { throw AppError.noCard }
        let checked = try reader.checkKeys(candidates: candidates, sectors: requested,
                                          expectedUID: original.uid, scanMode: scanMode,
                                          progress: progress, token: token)
        let target = checked.target
        let sectors = try WCopyReader.keyCheckSectors(requested, sectorCount: target.kind.sectorCount)
        var results = checked.sectorKeys
        var blocks = checked.blocks
        var attempts = checked.attempts

        func snapshot() -> KeyCheckOutcome {
            let missing = sectors.flatMap { sector -> [Int] in
                let first = CardLayout.firstBlock(of: sector)
                return (first..<(first + CardLayout.blockCount(in: sector))).filter { blocks[$0] == nil }
            }
            return KeyCheckOutcome(target: target, sectorKeys: results, blocks: blocks,
                                   failedBlocks: missing, attempts: attempts, candidateCount: checked.candidateCount)
        }
        func checkSameCard() throws {
            try token.check()
            guard let current = try reader.selectTarget() else { throw AppError.noCard }
            guard current.uid == target.uid, current.atqa == target.atqa, current.sak == target.sak else {
                throw AppError.operation("卡片已更换，自动恢复已停止；已读数据保留")
            }
        }
        func readSector(_ sector: Int, key: String, type: KeyType) throws {
            let first = CardLayout.firstBlock(of: sector)
            for block in first..<(first + CardLayout.blockCount(in: sector)) {
                try token.check()
                guard blocks[block] == nil else { continue }
                // A failed read can poison the authentication session. Reset for each missing block.
                try NestedRecoverySession(transport: reader, target: target, logger: logger).configureForAuth()
                attempts += 1
                guard try reader.verifySectorKey(keyHex: key, sector: sector, type: type,
                                                 target: target, token: token) else { continue }
                if let data = try reader.readBlock(block) {
                    blocks[block] = data
                    if CardLayout.isTrailer(block), CardLayout.keyBIsReadableData(in: data) == true {
                        // A readable trailer field is data until a separate authentication proves otherwise.
                        if results[sector]?.keyB == nil {
                            results[sector]?.keyB = HexCodec.string(data.suffix(6))
                            results[sector]?.keyBAuthenticates = false
                        }
                    }
                }
            }
        }

        checkpoint(snapshot())
        for round in 0..<rounds {
            try checkSameCard()
            let unresolved = Self.unresolvedSectors(sectors: sectors, blocks: blocks)
            if unresolved.isEmpty { break }
            let entries: [(Int, String, KeyType)] = results.values.sorted { $0.sector < $1.sector }.flatMap { result in
                var values: [(Int, String, KeyType)] = []
                if let a = result.keyA { values.append((result.sector, a, .a)) }
                if let b = result.keyB, result.keyBAuthenticates == true { values.append((result.sector, b, .b)) }
                return values
            }
            guard !entries.isEmpty else {
                logger("没有已验证密钥可作为恢复入口；已读数据保留，未启动无效重复")
                break
            }
            logger("自动恢复第 \(round + 1)/\(rounds) 轮：未读扇区 \(unresolved.map(String.init).joined(separator: ", "))")
            let entry = entries[round % entries.count]
            for (index, sector) in unresolved.enumerated() {
                try checkSameCard()
                progress(Double(index) / Double(unresolved.count), "第 \(round + 1)/\(rounds) 轮 · 扇区 \(sector)")
                for type in [KeyType.a, .b] {
                    try token.check()
                    if Self.unresolvedSectors(sectors: [sector], blocks: blocks).isEmpty { break }
                    let existing = type == .a ? results[sector]?.keyA :
                        (results[sector]?.keyBAuthenticates == true ? results[sector]?.keyB : nil)
                    if let existing {
                        try readSector(sector, key: existing, type: type)
                        if Self.unresolvedSectors(sectors: [sector], blocks: blocks).isEmpty { break }
                    }
                    let session = NestedRecoverySession(transport: reader, target: target, logger: logger)
                    do {
                        let seed = try HexCodec.data(from: entry.1, expectedBytes: 6)
                        guard let recovered = try session.recoverCalibratedKey(
                            exploitSector: entry.0, exploitKey: seed, exploitType: entry.2,
                            targetSector: sector, targetType: type, warmupStart: round * 4,
                            progress: { value, text in
                                progress((Double(index) + value) / Double(unresolved.count), "第 \(round + 1)/\(rounds) 轮 · \(text)")
                            }, token: token) else {
                            logger("扇区 \(sector) Key \(type.rawValue)：本轮未得到已验证密钥")
                            continue
                        }
                        try checkSameCard()
                        try session.configureForAuth()
                        attempts += 1
                        guard try reader.verifySectorKey(keyHex: recovered, sector: sector, type: type,
                                                         target: target, token: token) else { continue }
                        if type == .a { results[sector]?.keyA = recovered }
                        else { results[sector]?.keyB = recovered; results[sector]?.keyBAuthenticates = true }
                        try readSector(sector, key: recovered, type: type)
                        logger("扇区 \(sector)：密钥已验证，已补读数据")
                        checkpoint(snapshot())
                    } catch {
                        try token.check()
                        if case AppError.noCard = error { throw error }
                        // Recheck identity before continuing with any other sector.
                        logger("扇区 \(sector) Key \(type.rawValue) 本轮停止：\(error.localizedDescription)")
                        try checkSameCard()
                        if case AppError.transport = error { throw error }
                    }
                }
                checkpoint(snapshot())
            }
        }
        let final = snapshot()
        checkpoint(final)
        let remaining = Self.unresolvedSectors(sectors: sectors, blocks: blocks)
        progress(1, remaining.isEmpty ? "全部所选扇区已读出" : "达到恢复轮数，仍未读出：\(remaining.map(String.init).joined(separator: ", "))")
        return final
    }
}
