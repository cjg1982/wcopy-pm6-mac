import Foundation
import XCTest
@testable import WCopyNFCMac

final class CardCopyModeTests: XCTestCase {
    func testCompleteRequiresFullDumpAndValidManufacturer() throws {
        let dump = try fixture()
        XCTAssertNoThrow(try CardCopyMode.complete.validate(dump))
        var partial = dump
        partial.blocks.removeValue(forKey: "22")
        XCTAssertThrowsError(try CardCopyMode.complete.validate(partial))
        XCTAssertNoThrow(try CardCopyMode.normal.validate(partial))
        var missingKey = dump
        missingKey.sectorKeys = nil
        XCTAssertThrowsError(try CardCopyMode.complete.validate(missingKey))
        var badBCC = dump
        badBCC.blocks["0"] = String(repeating: "00", count: 16)
        XCTAssertThrowsError(try CardCopyMode.complete.validate(badBCC))
        var badAccess = dump
        badAccess.blocks["3"] = String(repeating: "00", count: 16)
        XCTAssertThrowsError(try CardCopyMode.complete.validate(badAccess))
        XCTAssertFalse(CardCopyMode.normal.includesProtectedBlocks)
        XCTAssertTrue(CardCopyMode.complete.includesProtectedBlocks)
    }
    private func fixture() throws -> DumpDocument {
        var data = Data(repeating: 0, count: 1024)
        data.replaceSubrange(0..<5, with: [0x11,0x22,0x33,0x44,0x44])
        let trailer = try HexCodec.data(from: "FFFFFFFFFFFFFF078069FFFFFFFFFFFF")
        for block in stride(from: 3, to: 64, by: 4) {
            data.replaceSubrange((block*16)..<(block*16+16), with: trailer)
        }
        return try DumpDocument.fromMFD(data)
    }
}
