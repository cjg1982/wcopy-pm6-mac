import Foundation
import XCTest
@testable import WCopyNFCMac

final class ProtocolTests: XCTestCase {
    func testBridgePM6AuthenticationMappingIsScopedToAuthentication() {
        var request = Data([0xD4, 0x40, 1, 0x60, 27])
        request.append(Data(repeating: 0xFF, count: 6))
        request.append(Data([0x11, 0x22, 0x33, 0x44]))
        let rejection = Data([0xD5, 0x41, 0xFD, 0x90, 0])
        XCTAssertEqual(LibNFCBridge.normalizePM6AuthenticationResponse(rejection, request: request, enabled: true), Data([0xD5, 0x41, 0x14, 0x90, 0]))
        XCTAssertEqual(LibNFCBridge.normalizePM6AuthenticationResponse(rejection, request: request, enabled: false), rejection)
        request[3] = 0x30
        XCTAssertEqual(LibNFCBridge.normalizePM6AuthenticationResponse(rejection, request: request, enabled: true), rejection)
        XCTAssertEqual(LibNFCBridge.normalizePM6AuthenticationResponse(rejection, request: Data(), enabled: true), rejection)
    }
    func testPM6AuthenticationRejectionRequiresExactFirmwareResponse() throws {
        let rejection = Data([0xD5, 0x41, 0xFD, 0x90, 0x00])
        XCTAssertFalse(try WCopyReader.mifareAuthenticationSucceeded(rejection, pm6Compatibility: true))
        XCTAssertThrowsError(try WCopyReader.mifareAuthenticationSucceeded(rejection))
        for response in [Data([0xD5, 0x41, 0x3D]), Data([0xD5, 0x41, 0xFD]),
                         Data([0xD5, 0x41, 0xFD, 0x6F, 0]), Data([0xD5, 0x42, 0xFD, 0x90, 0])] {
            XCTAssertThrowsError(try WCopyReader.mifareAuthenticationSucceeded(response, pm6Compatibility: true))
        }
        XCTAssertTrue(try WCopyReader.mifareAuthenticationSucceeded(Data([0xD5, 0x41, 0, 0x90, 0]), pm6Compatibility: true))
    }
    func testPM6DiscoveryAllowListPreservesExistingReaders() {
        XCTAssertEqual(wcopyVendorID, 0x0416)
        XCTAssertEqual(Set(supportedProductIDs), Set([0xB008, 0xB029, 0xB030]))
    }

    func testPM6CapturedFirmwareResponseAndValidation() throws {
        let query = Data([0xFF, 0x00, 0x68])
        let captured = try HexCodec.data(from: "021B690177436F7079204E53523132322D4820563730314132C8FD")
        let expected = Data("wCopy NSR122-H V701A2".utf8)
        XCTAssertEqual(WCopyReader.parseResponse(captured, sequence: 0, content: query, commandHeader: true), expected)
        XCTAssertNil(WCopyReader.parseResponse(captured, sequence: 0, content: query, commandHeader: false))
        XCTAssertNil(WCopyReader.parseResponse(captured, sequence: 0, content: Data([0xFF, 0, 0x69]), commandHeader: true))
        var corrupt = captured
        corrupt[4] ^= 1
        XCTAssertNil(WCopyReader.parseResponse(corrupt, sequence: 0, content: query, commandHeader: true))
        XCTAssertNil(WCopyReader.parseResponse(Data(captured.dropLast()), sequence: 0, content: query, commandHeader: true))
    }

    func testKeyCheckSectorSelection() throws {
        XCTAssertEqual(try WCopyReader.keyCheckSectors([6], sectorCount: 16), [6])
        XCTAssertEqual(try WCopyReader.keyCheckSectors([6, 0, 6], sectorCount: 16), [0, 6])
        XCTAssertEqual(try WCopyReader.keyCheckSectors(nil, sectorCount: 16), Array(0..<16))
        XCTAssertThrowsError(try WCopyReader.keyCheckSectors([], sectorCount: 16))
        XCTAssertThrowsError(try WCopyReader.keyCheckSectors([-1], sectorCount: 16))
        XCTAssertThrowsError(try WCopyReader.keyCheckSectors([6], sectorCount: 5))
    }

    func testKeyCheckRetriesAreBoundedAndStopOnSuccess() throws {
        var attempts = 0
        let result: Int = try WCopyReader.retryKeyCheck(rounds: 3, token: nil, attempt: { _ in
            attempts += 1
            if attempts < 3 { throw AppError.transport("fixture") }
            return 42
        }, onFailure: { _, _ in })
        XCTAssertEqual(result, 42)
        XCTAssertEqual(attempts, 3)
        attempts = 0
        XCTAssertThrowsError(try WCopyReader.retryKeyCheck(rounds: 3, token: nil, attempt: { _ -> Int in
            attempts += 1; throw AppError.transport("0x3D")
        }, onFailure: { _, _ in }))
        XCTAssertEqual(attempts, 3)
        attempts = 0
        XCTAssertThrowsError(try WCopyReader.retryKeyCheck(rounds: 3, token: nil, attempt: { _ -> Int in
            attempts += 1; throw AppError.noCard
        }, onFailure: { _, _ in }))
        XCTAssertEqual(attempts, 1)
        let token = CancellationToken(); token.cancel()
        XCTAssertThrowsError(try WCopyReader.retryKeyCheck(rounds: 3, token: token, attempt: { _ in 42 }, onFailure: { _, _ in }))
    }

    func testBuildAndParseFrame() throws {
        let output = try WCopyReader.buildFrame(sequence: 0x0C12, content: Data([0xFF, 0x00, 0x68]))
        XCTAssertEqual(output.count, 64)
        XCTAssertEqual(output.prefix(7), Data([0x01, 0x09, 0x12, 0x0C, 0xFF, 0x00, 0x68]))
        XCTAssertEqual(output[8], 0xFE)

        var input = Data([0x02, 0x09, 0x13, 0x0C, 0xAA, 0xBB, 0xCC])
        input.append(WCopyReader.checksum(input))
        input.append(0xFD)
        input.append(Data(repeating: 0, count: 55))
        XCTAssertEqual(WCopyReader.parseInputFrame(input, expectedSequence: 0x0C13), Data([0xAA, 0xBB, 0xCC]))

        input[7] ^= 0x01
        XCTAssertNil(WCopyReader.parseInputFrame(input, expectedSequence: 0x0C13))
    }

    func testCardLayoutFor4K() {
        XCTAssertEqual(CardLayout.firstBlock(of: 31), 124)
        XCTAssertEqual(CardLayout.firstBlock(of: 32), 128)
        XCTAssertEqual(CardLayout.trailerBlock(of: 32), 143)
        XCTAssertEqual(CardLayout.sector(containing: 255), 39)
        XCTAssertTrue(CardLayout.isTrailer(255))
    }

    func testSAK19CustomClassicDetection() {
        XCTAssertEqual(
            CardKind.detect(sak: 0x19, atqa: 0x0004, uidLength: 4),
            .customClassic1K
        )
        XCTAssertEqual(
            CardKind.detect(sak: 0x19, atqa: 0x0044, uidLength: 4),
            .unknown
        )
        XCTAssertEqual(CardScanMode.classic1K.forcedKind, .classic1K)
        XCTAssertEqual(CardScanMode.sak19Classic1K.forcedKind, .customClassic1K)
        XCTAssertEqual(CardScanMode.classic2K.forcedKind?.sectorCount, 32)
        XCTAssertEqual(CardScanMode.classic4K.forcedKind?.blockCount, 256)
        XCTAssertNil(CardScanMode.automatic.forcedKind)
    }

    func testSAK19UIDDerivedKeyCandidate() throws {
        let uid = try HexCodec.data(from: "12345678", expectedBytes: 4)
        XCTAssertEqual(SAK19Compatibility.uidDerivedKeyCandidate(uid), "26123456782E")
        XCTAssertNil(SAK19Compatibility.uidDerivedKeyCandidate(Data(repeating: 0, count: 7)))
    }

    func testLegacySAK19CardTypeStillImports() throws {
        let json = Data(#"{"uid":"12345678","cardType":"定制 MIFARE Classic 1K (SAK 19)","atqa":"0004","sak":"19","key":"FFFFFFFFFFFF","key_type":"A","blocks":{"0":"12345678080000000000000000000000"}}"#.utf8)
        let dump = try DumpDocument.fromJSON(json)
        XCTAssertEqual(dump.inferredKind, .customClassic1K)
        XCTAssertEqual(dump.cardType, CardKind.customClassic1K.rawValue)
    }

    func testSectorTrailerKeyBAccessCondition() throws {
        let factory = try HexCodec.data(from: "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", expectedBytes: 16)
        XCTAssertEqual(CardLayout.keyBIsReadableData(in: factory), true)

        let authenticationKeyB = try HexCodec.data(from: "FFFFFFFFFFFF7F078869FFFFFFFFFFFF", expectedBytes: 16)
        XCTAssertEqual(CardLayout.keyBIsReadableData(in: authenticationKeyB), false)

        XCTAssertNil(CardLayout.keyBIsReadableData(in: Data(repeating: 0, count: 16)))
    }

    func testManufacturerBlockUIDAndBCCValidation() throws {
        let uid = try HexCodec.data(from: "AABBCCDD", expectedBytes: 4)
        let valid = try HexCodec.data(from: "AABBCCDD00FF00112233445566778899", expectedBytes: 16)
        let invalidBCC = try HexCodec.data(from: "AABBCCDDEEFF11223344556677889900", expectedBytes: 16)
        XCTAssertTrue(CardLayout.manufacturerBlock(valid, matchesUID: uid))
        XCTAssertFalse(CardLayout.manufacturerBlock(invalidBCC, matchesUID: uid))
        XCTAssertFalse(CardLayout.manufacturerBlock(valid, matchesUID: Data(repeating: 0, count: 7)))
    }

    func testMifareAuthenticationStatusClassification() throws {
        XCTAssertTrue(try WCopyReader.mifareAuthenticationSucceeded(Data([0xD5, 0x41, 0x00])))
        XCTAssertFalse(try WCopyReader.mifareAuthenticationSucceeded(Data([0xD5, 0x41, 0x14])))
        XCTAssertThrowsError(try WCopyReader.mifareAuthenticationSucceeded(Data([0xD5, 0x41, 0x01])))
        XCTAssertThrowsError(try WCopyReader.mifareAuthenticationSucceeded(Data([0xD5, 0x4B, 0x00])))
    }

    func testSectorParsing() throws {
        XCTAssertEqual(try parseSectors("0-3, 7, 9-10"), [0, 1, 2, 3, 7, 9, 10])
        XCTAssertThrowsError(try parseSectors("4-2"))
        XCTAssertThrowsError(try parseSectors("40"))
    }

    func testDictionaryParserHandlesCommonFormats() {
        let text = """
        # comment
        FFFFFFFFFFFF
        0xa0a1a2a3a4a5 ; inline comment
        00 00 00 00 00 00
        FFFFFFFFFFFF
        invalid
        """
        let result = MifareKeyDictionary.parse(text)
        XCTAssertEqual(result.keys, ["FFFFFFFFFFFF", "A0A1A2A3A4A5", "000000000000"])
        XCTAssertEqual(result.duplicateCount, 1)
        XCTAssertEqual(result.ignoredLines, 1)
    }

    func testDictionaryPresetsAreDeduplicatedAndValid() {
        for preset in KeyDictionaryPreset.allCases where preset != .customOnly {
            XCTAssertEqual(Set(preset.keys).count, preset.keys.count)
            XCTAssertTrue(preset.keys.allSatisfy { (try? HexCodec.data(from: $0, expectedBytes: 6)) != nil })
        }
        XCTAssertGreaterThan(MifareKeyDictionary.commonKeys.count, MifareKeyDictionary.quickKeys.count)
        XCTAssertGreaterThan(MifareKeyDictionary.weakPatternKeys.count, MifareKeyDictionary.commonKeys.count)
    }

    func testDictionaryMergeKeepsProbabilityOrder() {
        let merged = MifareKeyDictionary.merged([
            ["FFFFFFFFFFFF", "000000000000"],
            ["ffffffffffff", "A0A1A2A3A4A5"]
        ])
        XCTAssertEqual(merged, ["FFFFFFFFFFFF", "000000000000", "A0A1A2A3A4A5"])
    }

    func testMifareKeyClipboardNormalization() throws {
        XCTAssertEqual(try normalizeMifareKey("0xa0:a1:a2:a3:a4:a5\n"), "A0A1A2A3A4A5")
        XCTAssertEqual(try normalizeMifareKey("FF FF FF FF FF FF"), "FFFFFFFFFFFF")
        XCTAssertThrowsError(try normalizeMifareKey("A0A1A2"))
        XCTAssertThrowsError(try normalizeMifareKey("NOT-A-KEY"))
    }

    func testCLIOptionParsing() throws {
        let options = try CLIOptions([
            "--device-index=2", "--dictionary", "first.dic", "--dictionary", "second.keys",
            "--pretty", "--verbose"
        ])
        XCTAssertEqual(options.value("device-index"), "2")
        XCTAssertEqual(options.allValues("dictionary"), ["first.dic", "second.keys"])
        XCTAssertTrue(options.hasFlag("pretty"))
        XCTAssertTrue(options.hasFlag("verbose"))
        XCTAssertThrowsError(try options.validate(valueOptions: ["device-index"], flagOptions: ["pretty"]))
    }

    func testCLIRejectsMissingOptionValue() {
        XCTAssertThrowsError(try CLIOptions(["--key"]))
        XCTAssertThrowsError(try CLIOptions(["--device-index="]))
        XCTAssertThrowsError(try CLIOptions(["--key", "-h"]))
    }

    func testCLIRejectsRepeatedSingletonOption() throws {
        let options = try CLIOptions(["--uid", "AABBCCDD", "--uid", "11223344"])
        XCTAssertThrowsError(try options.validate(valueOptions: ["uid"], flagOptions: []))
    }

    func testCLIParsesCardModeAndKeyType() throws {
        XCTAssertEqual(try WCopyCLI.parseCardMode(nil), .automatic)
        XCTAssertEqual(try WCopyCLI.parseCardMode("sak19"), .sak19Classic1K)
        XCTAssertEqual(try WCopyCLI.parseCardMode("1k"), .classic1K)
        XCTAssertEqual(try WCopyCLI.parseCardMode("classic4k"), .classic4K)
        XCTAssertEqual(try WCopyCLI.parseKeyType("b"), .b)
        XCTAssertThrowsError(try WCopyCLI.parseCardMode("8k"))
        XCTAssertThrowsError(try WCopyCLI.parseKeyType("C"))
    }

    func testJSONCompatibilityWithUpstream() throws {
        let json = Data(#"{"uid":"AABBCCDD","key":"FFFFFFFFFFFF","key_type":"A","blocks":{"0":"00112233445566778899AABBCCDDEEFF"}}"#.utf8)
        let dump = try DumpDocument.fromJSON(json)
        XCTAssertEqual(dump.version, 1)
        XCTAssertEqual(dump.blocks.count, 1)
        XCTAssertEqual(dump.uid, "AABBCCDD")
    }

    func testJSONRejectsInvalidSectorKeyBeforeRestore() {
        let json = Data(#"{"uid":"AABBCCDD","key":"FFFFFFFFFFFF","key_type":"A","blocks":{"0":"00112233445566778899AABBCCDDEEFF"},"sectorKeys":{"0":{"a":"NOTAKEY"}}}"#.utf8)
        XCTAssertThrowsError(try DumpDocument.fromJSON(json))
    }

    func testJSONRejectsEmptyDumpAndNoncanonicalBlockAliases() {
        let empty = Data(#"{"uid":"AABBCCDD","key":"FFFFFFFFFFFF","key_type":"A","blocks":{}}"#.utf8)
        XCTAssertThrowsError(try DumpDocument.fromJSON(empty))

        let aliases = Data(#"{"uid":"AABBCCDD","key":"FFFFFFFFFFFF","key_type":"A","blocks":{"1":"00112233445566778899AABBCCDDEEFF","01":"FFEEDDCCBBAA99887766554433221100"}}"#.utf8)
        XCTAssertThrowsError(try DumpDocument.fromJSON(aliases))
    }

    func testMFDExportRejectsNoncanonicalBlockAliasWithoutTrap() {
        let dump = DumpDocument(
            uid: "AABBCCDD",
            blocks: [
                "1": "00112233445566778899AABBCCDDEEFF",
                "01": "FFEEDDCCBBAA99887766554433221100"
            ]
        )
        XCTAssertThrowsError(try dump.mfdData())
    }

    func testMFDImportExport() throws {
        let source = Data((0..<1024).map { UInt8($0 % 251) })
        let dump = try DumpDocument.fromMFD(source)
        XCTAssertEqual(dump.inferredKind, .classic1K)
        XCTAssertEqual(try dump.mfdData(), source)
        XCTAssertEqual(dump.sectorKeys?["0"]?.a, HexCodec.string(source.subdata(in: 48..<54)))
    }

    func test2KMFDImportExport() throws {
        let source = Data((0..<2048).map { UInt8($0 % 251) })
        let dump = try DumpDocument.fromMFD(source)
        XCTAssertEqual(dump.inferredKind, .classic2K)
        XCTAssertEqual(dump.blocks.count, 128)
        XCTAssertEqual(try dump.mfdData(), source)
    }

    func testMFDExportRequiresBothTrailerKeys() throws {
        var blocks: [String: String] = [:]
        for block in 0..<64 { blocks[String(block)] = String(repeating: "00", count: 16) }
        let dump = DumpDocument(
            uid: "00000000",
            cardType: CardKind.classic1K.rawValue,
            blocks: blocks,
            sectorKeys: ["0": SectorKeys(a: "FFFFFFFFFFFF", b: nil)]
        )
        XCTAssertThrowsError(try dump.mfdData())
    }

    func testLibNFCFrameRoundTrip() {
        let payload = Data([0xD4, 0x4A, 0x01, 0x00])
        let frame = LibNFCBridge.buildFrame(payload)
        let parsed = LibNFCBridge.nextFrame(from: Data([0x55, 0x55]) + frame)
        XCTAssertEqual(parsed?.payload, payload)
        XCTAssertEqual(parsed?.remaining, Data())
    }

    func testLibNFCNormalizesOnlyMatchingSAK19Target() {
        let response = Data([0xD5, 0x4B, 0x01, 0x01, 0x00, 0x04, 0x19, 0x04, 0x48, 0xC8, 0x40, 0x3C])
        let normalized = LibNFCBridge.normalizeSAK19ForLegacyLibNFC(response)
        XCTAssertEqual(normalized[6], 0x08)
        XCTAssertEqual(normalized.prefix(6), response.prefix(6))
        XCTAssertEqual(normalized.suffix(from: 7), response.suffix(from: 7))

        var otherATQA = response
        otherATQA[5] = 0x44
        XCTAssertEqual(LibNFCBridge.normalizeSAK19ForLegacyLibNFC(otherATQA), otherATQA)
    }

    func testGUIBridgeExtractsMfocExitCodeFromCLIOutput() {
        let output = Data("""
        [wcopy-nfc] libnfc command finished
        {"command":"bridge","data":{"command":"mfoc -O /tmp/card.mfd","exitCode":1},"ok":true,"schemaVersion":1}
        """.utf8)
        XCTAssertEqual(AppModel.bridgeExitCode(from: output), 1)
        XCTAssertNil(AppModel.bridgeExitCode(from: Data("not json".utf8)))
    }

    func testGUIBridgeFiltersOnlyHighFrequencyProtocolLogs() {
        XCTAssertFalse(AppModel.shouldDisplayCLIBridgeLogLine("[wcopy-nfc] BRIDGE READ 19 bytes: 00 00 FF"))
        XCTAssertFalse(AppModel.shouldDisplayCLIBridgeLogLine("[wcopy-nfc] libnfc InListPassiveTarget raw response (12B): D5 4B"))
        XCTAssertFalse(AppModel.shouldDisplayCLIBridgeLogLine("[wcopy-nfc] libnfc 兼容：仅向旧工具将 SAK 19 报告为 Classic 1K SAK 08"))
        XCTAssertTrue(AppModel.shouldDisplayCLIBridgeLogLine("Auth with all sectors succeeded"))
        XCTAssertTrue(AppModel.shouldDisplayCLIBridgeLogLine("[wcopy-nfc] BRIDGE TIMEOUT for D4 40"))
    }
}
