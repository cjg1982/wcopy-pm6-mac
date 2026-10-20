import Foundation
import XCTest
@testable import WCopyNFCMac

final class DumpVerificationTests: XCTestCase {
    func testNormalBlockMismatchAndLengthRejection() {
        let zero = Data(repeating: 0, count: 16)
        var changed = zero; changed[7] = 1
        XCTAssertTrue(WCopyReader.verificationBytesMatch(block: 1, expected: zero, actual: zero))
        XCTAssertFalse(WCopyReader.verificationBytesMatch(block: 1, expected: zero, actual: changed))
        XCTAssertFalse(WCopyReader.verificationBytesMatch(block: 1, expected: zero, actual: Data()))
    }
    func testReadableTrailerFieldsComparedWithoutHiddenKeyA() throws {
        let expected = try HexCodec.data(from: "FFFFFFFFFFFFFF078069FFFFFFFFFFFF")
        var read = expected
        read.replaceSubrange(0..<6, with: Data(repeating: 0, count: 6))
        XCTAssertTrue(WCopyReader.verificationBytesMatch(block: 3, expected: expected, actual: read))
        read[10] = 0
        XCTAssertFalse(WCopyReader.verificationBytesMatch(block: 3, expected: expected, actual: read))
        read = expected; read[9] ^= 1
        XCTAssertFalse(WCopyReader.verificationBytesMatch(block: 3, expected: expected, actual: read))
    }
    func testUnreadableOrFailedKeysPreventPass() {
        XCTAssertFalse(DumpVerificationResult(checked: 0, matched: 0, mismatchedBlocks: [], unreadableBlocks: [], failedKeySectors: []).passed)
        XCTAssertFalse(DumpVerificationResult(checked: 2, matched: 1, mismatchedBlocks: [], unreadableBlocks: [2], failedKeySectors: []).passed)
        XCTAssertFalse(DumpVerificationResult(checked: 2, matched: 2, mismatchedBlocks: [], unreadableBlocks: [], failedKeySectors: [0]).passed)
        XCTAssertTrue(DumpVerificationResult(checked: 2, matched: 2, mismatchedBlocks: [], unreadableBlocks: [], failedKeySectors: []).passed)
    }
}
