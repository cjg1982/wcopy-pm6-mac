import Foundation
import XCTest
@testable import WCopyNFCMac

/// Reference vectors generated from mfoc/crapto1 (crypto1) and libnfc pn53x
/// (wrap/unwrap framing). The generator is an offline C tool; these vectors pin
/// the native reimplementation to the reference behavior.
private let referenceVectors = """
=== filter ===
0005df45 1
0003c45e 1
000996ee 1
0008cea8 0
000aeb10 0
000dda31 0
0009cfcd 1
000d6ce5 0
=== bit ===
f922c6e861b1 f9e3b7b3 59023e3d
197f2e715289 b70ccd21 c2cccdfb
c17db3a57455 3884ef20 faa0ce92
07f48f3013a6 9a8d3b91 e01d3adb
b1c32b4e6a21 86c9c55a 3e3d56ed
d9f9e0f2a3a5 68d3dd7a b50952df
c6b29a454b03 cc42effb ec0f6c8b
9541bb6586bb b5edfac2 63544f47
=== byte ===
5d71bb997c0e 2f 1 77
763b42617c9e 33 1 82
74046f19615a fd 1 15
5118e50fc646 ca 0 86
5c6373a98241 c8 0 f2
5e42f4a9f012 11 0 99
3758f44083b0 cf 1 5c
627272546d4c ce 1 a8
=== word ===
edafc3ae08ea f8085517 1 b3dd1e9b
b6bb13c037a5 9e1f965a 1 05c0a2e7
74a968b1f2e4 392a4546 0 24f65bfd
8eed60317610 78088104 0 4ebf864a
c562cdcd14a7 0ef97288 1 b63719c9
b058614b1ca5 e629296b 1 5f859b6e
a3a2207c34b1 a7e8836c 0 9252f720
ecc5719e3d7f fffee2e6 0 fd265f7e
=== prng ===
55637353 199 e1f75ac3
c0edc88b 669 c38355ff
33b74fdf 903 3c157d1a
ad3b6e13 399 97990c48
26252480 196 b6a7901f
9af0fb32 727 e6bdcc60
0c62b80a 961 5251a63d
e249aadd 858 0efd047a
=== nonce_dist ===
1d7b9692 d1528002 26967
bd9d7f46 ab619e3a 29964
5c12e56b 692c514b 63123
018f35e3 4c4098dd 23686
921a7729 6f5fdfa0 63023
1b317b67 27a5aae6 53882
d0d31fa0 4fcc9346 55985
b5175fc7 e758ae3a 40737
=== validate ===
11111111 0
1111ffcf 1
ffcf80e3 1
80e30c20 1
0c200e1d 1
=== lfsr_recovery ===
974b972a47e5 39f2d0c0 8b840a36 1b8e2559 70624 1 efaa3ab36c811256
7be234de52fc b9c8c24a aabb3cd2 37eb685e 79375 1 979c45e68411a43c
5630132dad27 c4c9038f 3566de65 a49747d4 104211 1 c5a15c8989306d4e
fde7bf2a4081 e547ba51 a850089a 163da0c4 62069 1 e58d56784b387535
54397539bd0a b643cd10 a6c856a5 5fb85b57 95134 1 83aabdeab831238b
5ff8ed10ecfe 8c8de44b e4a36003 7ffcdcdf 143336 1 1b0450dd86830358
=== crc ===
6008 bdf7
600f 0283
610b fedc
603f 81b2
000102030405 28da
3008 4a24
=== wrap ===
8 72 9 59fd80b7e11ee91de3 597ee036ee4877c6 10101101
4 36 5 b00c30d804 b0060c9b 0000
8 72 9 3fb2faa8b2533c2bca 3f593e553be2ac94 01001101
4 36 5 457fe0c307 453ff8f8 1000
8 72 9 fb24060be92f9fa9d7 fb12c121fef9a6af 01010001
4 36 5 ee2b250902 ee954941 1000
8 72 9 6b0f25c953a14d117b 6b874979156d45f6 10000000
4 36 5 8dd27fc302 8de9df58 0100
=== unwrap ===
72 64 8 713399f7b65e3f1562 7199e6deebfa54c4 10101100
36 32 4 6f1e03694a 6f8f404d 0101
72 64 8 4b450014199f9a301c 4b220022f1d4c238 10111000
36 32 4 15eb4228ec 15751085 1101
72 64 8 e82e52a7c319ed0af2 e817d4749c682be4 01101101
36 32 4 668d1a28b9 66460625 1101
72 64 8 061a5af66d8ebb4214 060d96bee6dc0a28 01110110
36 32 4 3abf009223 3a5f8072 1000
"""

private struct VectorReader {
    private let lines: [String]
    private var index = 0

    init(_ text: String) {
        lines = text.components(separatedBy: "\n")
    }

    mutating func section(_ name: String) {
        while index < lines.count && !lines[index].hasPrefix("=== \(name) ===") {
            index += 1
        }
        index += 1
    }

    mutating func next() -> [String] {
        let line = lines[index]
        index += 1
        return line.split(separator: " ").map(String.init)
    }
}

final class Crypto1Tests: XCTestCase {
    func testFilterMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("filter")
        for _ in 0 ..< 8 {
            let p = vectors.next()
            let x = UInt32(p[0], radix: 16)!
            XCTAssertEqual(Crypto1.filter(x), UInt8(p[1])!)
        }
    }

    func testBitMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("bit")
        for _ in 0 ..< 8 {
            let p = vectors.next()
            let key = UInt64(p[0], radix: 16)!
            let input = UInt32(p[1], radix: 16)!
            let expected = UInt32(p[2], radix: 16)!
            var state = Crypto1.create(key: key)
            var output: UInt32 = 0
            for i in 0 ..< 32 {
                output |= UInt32(Crypto1.bit(&state, input: UInt8((input >> UInt32(i)) & 1), isEncrypted: true)) << i
            }
            XCTAssertEqual(output, expected)
        }
    }

    func testByteMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("byte")
        for _ in 0 ..< 8 {
            let p = vectors.next()
            let key = UInt64(p[0], radix: 16)!
            let input = UInt8(p[1], radix: 16)!
            let encrypted = p[2] == "1"
            let expected = UInt8(p[3], radix: 16)!
            var state = Crypto1.create(key: key)
            XCTAssertEqual(Crypto1.byte(&state, input: input, isEncrypted: encrypted), expected)
        }
    }

    func testWordMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("word")
        for _ in 0 ..< 8 {
            let p = vectors.next()
            let key = UInt64(p[0], radix: 16)!
            let input = UInt32(p[1], radix: 16)!
            let encrypted = p[2] == "1"
            let expected = UInt32(p[3], radix: 16)!
            var state = Crypto1.create(key: key)
            XCTAssertEqual(Crypto1.word(&state, input: input, isEncrypted: encrypted), expected)
        }
    }

    func testPRNGMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("prng")
        for _ in 0 ..< 8 {
            let p = vectors.next()
            let nonce = UInt32(p[0], radix: 16)!
            let steps = UInt32(p[1])!
            let expected = UInt32(p[2], radix: 16)!
            XCTAssertEqual(Crypto1.prngSuccessor(nonce, steps), expected)
        }
    }

    func testNonceDistanceMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("nonce_dist")
        for _ in 0 ..< 8 {
            let p = vectors.next()
            let from = UInt32(p[0], radix: 16)!
            let to = UInt32(p[1], radix: 16)!
            XCTAssertEqual(Crypto1.nonceDistance(from: from, to: to), Int(p[2])!)
        }
    }

    func testValidatePRNGNonceMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("validate")
        for _ in 0 ..< 5 {
            let p = vectors.next()
            let nonce = UInt32(p[0], radix: 16)!
            XCTAssertEqual(Crypto1.validatePrngNonce(nonce), p[1] == "1")
        }
    }

    func testLFSRRecoveryMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("lfsr_recovery")
        for _ in 0 ..< 6 {
            let p = vectors.next()
            let key = UInt64(p[0], radix: 16)!
            let nt = UInt32(p[1], radix: 16)!
            let uid = UInt32(p[2], radix: 16)!
            let ks = UInt32(p[3], radix: 16)!
            let expectedCount = Int(p[4])!
            let containsKey = p[5] == "1"
            let expectedHash = UInt64(p[6], radix: 16)!

            let states = Crypto1.lfsrRecovery32(ks, input: nt ^ uid)
            var candidates: [UInt64] = []
            for var state in states {
                _ = Crypto1.rollbackWord(&state, input: nt ^ uid, fb: 0)
                candidates.append(Crypto1.getLFSR(from: state))
            }
            candidates.sort()
            XCTAssertEqual(candidates.count, expectedCount)

            var hash: UInt64 = 14695981039346656037
            for candidate in candidates {
                hash ^= candidate
                hash &*= 1099511628211
            }
            XCTAssertEqual(hash, expectedHash)
            XCTAssertEqual(candidates.contains(key), containsKey)
        }
    }

    func testCRC14443AMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("crc")
        for _ in 0 ..< 6 {
            let p = vectors.next()
            let data = try! HexCodec.data(from: p[0])
            let expected = p[1]
            let crc = Crypto1.crc14443A(data)
            XCTAssertEqual(String(format: "%02X%02X", crc & 0xFF, crc >> 8), expected.uppercased())
        }
    }

    func testWrapMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("wrap")
        for _ in 0 ..< 8 {
            let p = vectors.next()
            let nbytes = Int(p[0])!
            let frameBits = Int(p[1])!
            let frameBytes = Int(p[2])!
            let expectedFrame = p[3]
            let data = try! HexCodec.data(from: p[4])
            let parity = p[5].map { $0 == "1" ? UInt8(1) : UInt8(0) }

            let wrapped = MifareBitFraming.wrapFrame(data: data, parity: parity)
            XCTAssertEqual(MifareBitFraming.frameBits(forDataBits: nbytes * 8), frameBits)
            let prefix = wrapped.prefix(frameBytes).map { String(format: "%02X", $0) }.joined()
            XCTAssertEqual(prefix, expectedFrame.uppercased())
        }
    }

    func testUnwrapMatchesReference() {
        var vectors = VectorReader(referenceVectors)
        vectors.section("unwrap")
        for _ in 0 ..< 8 {
            let p = vectors.next()
            let frameBits = Int(p[0])!
            let frame = try! HexCodec.data(from: p[3])
            let expectedData = p[4]
            let expectedParity = p[5]

            let result = MifareBitFraming.unwrapFrame(frame: frame, frameBits: frameBits)
            let dataHex = result.data.map { String(format: "%02X", $0) }.joined()
            let parityBits = result.parity.map { $0 == 1 ? "1" : "0" }.joined()
            XCTAssertEqual(dataHex, expectedData.uppercased())
            XCTAssertEqual(parityBits, expectedParity)
        }
    }

    func testWrapUnwrapRoundTrip() {
        for nbytes in [4, 8] {
            for _ in 0 ..< 1000 {
                let data = Data((0 ..< nbytes).map { _ in UInt8.random(in: 0 ... 255) })
                let parity = (0 ..< nbytes).map { _ in UInt8.random(in: 0 ... 1) }
                let wrapped = MifareBitFraming.wrapFrame(data: data, parity: parity)
                let bits = MifareBitFraming.frameBits(forDataBits: nbytes * 8)
                let unwrapped = MifareBitFraming.unwrapFrame(frame: wrapped, frameBits: bits)
                XCTAssertEqual(unwrapped.data, data)
                XCTAssertEqual(unwrapped.parity, parity)
            }
        }
    }

    func testValidNonceAcceptsCorrectCandidate() throws {
        let key = try HexCodec.data(from: "A0A1A2A3A4A5", expectedBytes: 6)
        let uid: UInt32 = 0x48C8403C
        var card = Crypto1.create(key: Crypto1Tests.keyToUInt64(key))
        let nt: UInt32 = 0x9E4F5A12
        let ks = Crypto1.word(&card, input: nt ^ uid, isEncrypted: false)
        let ntEnc = nt ^ ks
        // Parity of the transmitted ciphertext: encrypted odd parity.
        var parity: [UInt8] = []
        var parityState = Crypto1.create(key: Crypto1Tests.keyToUInt64(key))
        for i in 0 ..< 4 {
            let plaintext = UInt8((nt >> UInt32(8 * (3 - i))) & 0xFF)
            _ = Crypto1.byte(&parityState, input: 0, isEncrypted: false)
            parity.append(Crypto1.oddParity8(plaintext) ^ Crypto1.filter(parityState.odd))
        }
        // Reader side parity check for the first three bytes.
        var received: [UInt8] = []
        for i in 0 ..< 3 {
            let ciphertext = UInt8((ntEnc >> UInt32(8 * (3 - i))) & 0xFF)
            received.append(Crypto1.oddParity8(ciphertext) != parity[i] ? 1 : 0)
        }
        XCTAssertTrue(Crypto1.validNonce(nt, ntEnc, ks, parity: received))

        // A wrong candidate that flips a checked byte must fail the parity gate.
        let wrong = nt ^ 0x80000000
        let wrongKs = ntEnc ^ wrong
        XCTAssertFalse(Crypto1.validNonce(wrong, ntEnc, wrongKs, parity: received))
    }

    static func keyToUInt64(_ data: Data) -> UInt64 {
        var value: UInt64 = 0
        for byte in data { value = (value << 8) | UInt64(byte) }
        return value
    }

    static func keyToUInt32(_ data: Data) -> UInt32 {
        UInt32(truncatingIfNeeded: keyToUInt64(data))
    }
}

/// Simulated MIFARE Classic card that follows the nested-attack wire protocol.
/// Used to exercise the native recovery end to end without hardware.
final class SimulatedMifareCard: NestedRecoveryTransport {
    let uid: Data
    private let keys: [Int: (a: Data, b: Data)]
    var blocks: [Int: Data] = [:]

    // Card PRNG. `prngSuccessor` preserves the 16-apart halves invariant, so
    // every nonce produced here is a valid PRNG nonce.
    private var nonceState: UInt32 = 0x1111FFCF
    private var firstNestedAfterBase = false

    private var cardKeyU64: UInt64 = 0
    private var cardState = Crypto1.State(odd: 0, even: 0)
    private var lastNt: UInt32 = 0
    private var registers: [UInt16: UInt8] = [:]

    init(uid: Data, keys: [Int: (a: Data, b: Data)]) {
        self.uid = uid
        self.keys = keys
    }

    private var uidLast4: UInt32 {
        var value: UInt32 = 0
        for i in (uid.count - 4) ..< uid.count {
            value = (value << 8) | UInt32(uid[i])
        }
        return value
    }

    private func nextNonce(advance: UInt32) -> UInt32 {
        nonceState = Crypto1.prngSuccessor(nonceState, advance)
        return nonceState
    }

    private func ntBytes(_ value: UInt32) -> Data {
        Data([
            UInt8((value >> 24) & 0xFF), UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)
        ])
    }

    private func appendEncryptedByte(_ state: inout Crypto1.State, plaintext: UInt8, to data: inout Data, parity: inout [UInt8]) {
        let encrypted = Crypto1.byte(&state, input: 0, isEncrypted: false) ^ plaintext
        data.append(encrypted)
        parity.append(Crypto1.filter(state.odd) ^ Crypto1.oddParity8(plaintext))
    }

    // MARK: - NestedRecoveryTransport

    func rawPN532(_ bytes: Data) throws -> Data {
        guard bytes.count >= 2, bytes[0] == 0xD4 else {
            throw AppError.operation("模拟器收到无效 PN532 命令")
        }
        switch bytes[1] {
        case 0x14:
            return Data([0xD5, 0x15, 0x00])
        case 0x32:
            return Data([0xD5, 0x33, 0x00])
        case 0x4A:
            var response = Data([0xD5, 0x4B, 0x01, 0x01, 0x00, 0x04, 0x08, 0x04])
            response.append(uid)
            return response
        case 0x42:
            return try Data([0xD5, 0x43, 0x00]) + handlePlainTransceive(bytes.subdata(in: 2 ..< bytes.count))
        case 0x06:
            let address = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
            return Data([0xD5, 0x07, registers[address] ?? 0])
        case 0x08:
            let address = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
            registers[address] = bytes[4]
            return Data([0xD5, 0x09, 0x00])
        default:
            throw AppError.operation("模拟器未处理 PN532 命令 0x\(String(format: "%02X", bytes[1]))")
        }
    }

    func readRegister(_ address: UInt16) throws -> UInt8 {
        registers[address] ?? 0
    }

    func writeRegister(_ address: UInt16, value: UInt8) throws {
        registers[address] = value
    }

    func transceiveRawBits(data: Data, parity: [UInt8], timeout: TimeInterval) throws -> (data: Data, parity: [UInt8]) {
        switch data.count {
        case 8:
            return try handleEncryptedNrAr(data)
        case 4:
            return try handleEncryptedAuth(data)
        default:
            throw AppError.operation("模拟器收到意外的原始帧（\(data.count) 字节）")
        }
    }

    func authenticate(block: Int, uid: Data, key: Data, type: KeyType) throws -> Bool {
        let sector = CardLayout.sector(containing: block)
        guard let sectorKeys = keys[sector] else { return false }
        let expected = type == .a ? sectorKeys.a : sectorKeys.b
        return key == expected
    }

    func readBlock(_ block: Int) throws -> Data? {
        blocks[block]
    }

    // MARK: - Card logic

    private func handlePlainTransceive(_ tx: Data) throws -> Data {
        guard tx.count >= 2 else { throw AppError.operation("模拟器：明文命令过短") }
        let opcode = tx[0]
        let block = Int(tx[1])
        let sector = CardLayout.sector(containing: block)
        guard let sectorKeys = keys[sector] else {
            throw AppError.operation("模拟器：扇区 \(sector) 没有密钥")
        }
        let key = opcode == 0x60 ? sectorKeys.a : sectorKeys.b
        cardKeyU64 = Self.keyToUInt64(key)
        lastNt = nextNonce(advance: 0)
        cardState = Crypto1.create(key: cardKeyU64)
        _ = Crypto1.word(&cardState, input: lastNt ^ uidLast4, isEncrypted: false)
        firstNestedAfterBase = true
        return ntBytes(lastNt)
    }

    private func handleEncryptedNrAr(_ data: Data) throws -> (data: Data, parity: [UInt8]) {
        var plaintext = [UInt8]()
        for i in 0 ..< 8 {
            plaintext.append(Crypto1.byte(&cardState, input: 0, isEncrypted: false) ^ data[i])
        }
        var ntForward = Crypto1.prngSuccessor(lastNt, 32)
        for i in 0 ..< 4 {
            ntForward = Crypto1.prngSuccessor(ntForward, 8)
            guard plaintext[4 + i] == UInt8(ntForward & 0xFF) else {
                throw AppError.operation("模拟器：ar 验证失败（第 \(i) 字节）")
            }
        }
        // at = suc3(lastNt), encrypted with the word-convention keystream.
        let atWord = Crypto1.prngSuccessor(lastNt, 96)
        let atKeystream = Crypto1.word(&cardState, input: 0, isEncrypted: false)
        let atCipher = atWord ^ atKeystream
        var response = Data()
        var responseParity = [UInt8]()
        for i in 0 ..< 4 {
            let plaintextByte = UInt8((atWord >> UInt32(8 * (3 - i))) & 0xFF)
            response.append(UInt8((atCipher >> UInt32(8 * (3 - i))) & 0xFF))
            responseParity.append(Crypto1.oddParity8(plaintextByte) ^ UInt8((atKeystream >> UInt32((8 * (3 - i) ^ 24) & 31)) & 1))
        }
        XCTAssertEqual(Crypto1Tests.keyToUInt32(response), atCipher)
        return (response, responseParity)
    }

    private func handleEncryptedAuth(_ data: Data) throws -> (data: Data, parity: [UInt8]) {
        var command = [UInt8]()
        for i in 0 ..< 4 {
            command.append(Crypto1.byte(&cardState, input: 0, isEncrypted: false) ^ data[i])
        }
        let opcode = command[0]
        let block = Int(command[1])
        let sector = CardLayout.sector(containing: block)
        guard let sectorKeys = keys[sector] else {
            throw AppError.operation("模拟器：目标扇区 \(sector) 没有密钥")
        }
        let key = opcode == 0x60 ? sectorKeys.a : sectorKeys.b
        cardKeyU64 = Self.keyToUInt64(key)
        // The first nested nonce after a base auth is `distance` PRNG steps
        // ahead; subsequent ones keep the reader's suc(ntLast, 96) bookkeeping
        // consistent so every measured distance equals `distance`.
        lastNt = nextNonce(advance: firstNestedAfterBase ? 10 : 106)
        firstNestedAfterBase = false
        cardState = Crypto1.create(key: cardKeyU64)
        let ks = Crypto1.word(&cardState, input: lastNt ^ uidLast4, isEncrypted: false)
        let ntEnc = lastNt ^ ks
        var response = Data()
        var responseParity = [UInt8]()
        for i in 0 ..< 4 {
            let ntByte = UInt8((lastNt >> UInt32(8 * (3 - i))) & 0xFF)
            let ksByte = UInt8((ks >> UInt32(8 * (3 - i))) & 0xFF)
            response.append(ksByte ^ ntByte)
        }
        let plaintextBytes = (0 ..< 4).map { UInt8((lastNt >> UInt32(8 * (3 - $0))) & 0xFF) }
        responseParity = [
            Crypto1.oddParity8(plaintextBytes[0]) ^ UInt8((ks >> 16) & 1),
            Crypto1.oddParity8(plaintextBytes[1]) ^ UInt8((ks >> 8) & 1),
            Crypto1.oddParity8(plaintextBytes[2]) ^ UInt8(ks & 1),
            Crypto1.oddParity8(plaintextBytes[3]) ^ (Crypto1.filter(cardState.odd) & 1)
        ]
        XCTAssertEqual(Crypto1Tests.keyToUInt32(response), ntEnc)
        return (response, responseParity)
    }

    static func keyToUInt64(_ data: Data) -> UInt64 {
        var value: UInt64 = 0
        for byte in data { value = (value << 8) | UInt64(byte) }
        return value
    }
}

final class NestedRecoverySimulationTests: XCTestCase {
    private func makeCard() -> SimulatedMifareCard {
        let uid = try! HexCodec.data(from: "48C8403C", expectedBytes: 4)
        let keyA0 = try! HexCodec.data(from: "A0A1A2A3A4A5", expectedBytes: 6)
        let keyB0 = try! HexCodec.data(from: "B0B1B2B3B4B5", expectedBytes: 6)
        let targetKey = try! HexCodec.data(from: "112233445566", expectedBytes: 6)
        var keys: [Int: (a: Data, b: Data)] = [:]
        for sector in 0 ..< 16 {
            keys[sector] = (keyA0, keyB0)
        }
        keys[3] = (targetKey, keyB0)
        return SimulatedMifareCard(uid: uid, keys: keys)
    }

    func testRecoverKeyFindsUnknownSectorKey() throws {
        let card = makeCard()
        let uid = try! HexCodec.data(from: "48C8403C", expectedBytes: 4)
        let target = CardTarget(uid: uid, atqa: 0x0004, sak: 0x19, kind: .customClassic1K)
        let session = NestedRecoverySession(transport: card, target: target, logger: { _ in })

        let exploitKey = try! HexCodec.data(from: "A0A1A2A3A4A5", expectedBytes: 6)
        let candidates = try session.recoverKey(
            exploitSector: 0,
            exploitKey: exploitKey,
            exploitType: .a,
            targetSector: 3,
            targetType: .a,
            probes: 3,
            distanceProbes: 9,
            sets: 3,
            tolerance: 20
        )
        XCTAssertEqual(candidates, ["112233445566"])
    }

    func testCollectDistancesProducesConsistentMedian() throws {
        let card = makeCard()
        let uid = try! HexCodec.data(from: "48C8403C", expectedBytes: 4)
        let target = CardTarget(uid: uid, atqa: 0x0004, sak: 0x19, kind: .customClassic1K)
        let session = NestedRecoverySession(transport: card, target: target, logger: { _ in })
        let exploitKey = try! HexCodec.data(from: "A0A1A2A3A4A5", expectedBytes: 6)

        let median = try session.collectDistances(
            exploitKey: exploitKey,
            exploitType: .a,
            exploitSector: 0,
            numProbes: 9
        )
        XCTAssertEqual(median, 10)
    }

    func testSimulatedCardVerifiesRecoveredKey() throws {
        let card = makeCard()
        let recovered = try! HexCodec.data(from: "112233445566", expectedBytes: 6)
        let uid = try! HexCodec.data(from: "48C8403C", expectedBytes: 4)
        let trailer = CardLayout.trailerBlock(of: 3)
        XCTAssertTrue(try card.authenticate(block: trailer, uid: uid, key: recovered, type: .a))
    }
}
