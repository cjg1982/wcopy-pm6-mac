import Foundation
import XCTest
@testable import WCopyNFCMac

final class AutomaticSectorRecoveryTests: XCTestCase {
    func testOnlyIncompleteSectorsRemainIncludingLargeSectors() {
        var blocks: [Int: Data] = [:]
        for sector in [2, 6, 33] {
            let first = CardLayout.firstBlock(of: sector)
            for block in first..<(first + CardLayout.blockCount(in: sector)) {
                blocks[block] = Data(repeating: 0, count: 16)
            }
        }
        blocks.removeValue(forKey: 25)
        blocks.removeValue(forKey: CardLayout.firstBlock(of: 33) + 15)
        XCTAssertEqual(AutomaticSectorRecovery.unresolvedSectors(sectors: [2, 6, 33], blocks: blocks), [6, 33])
    }

    func testSyntheticSamplesRetainTheirGeneratedKey() throws {
        let key: UInt64 = 0x123456789ABC
        let uid: UInt32 = 0x11223344
        var intersection: Set<UInt64>?
        for plaintext: UInt32 in [0x12345678, 0x9ABCDEF0] {
            var state = Crypto1.create(key: key)
            let encrypted = plaintext ^ Crypto1.word(&state, input: plaintext ^ uid, isEncrypted: false)
            let candidates = try NestedRecoverySession.calibratedCandidates(plaintext: plaintext, encrypted: encrypted, uid: uid)
            XCTAssertTrue(candidates.contains(key))
            intersection = intersection.map { $0.intersection(candidates) } ?? candidates
        }
        XCTAssertTrue(intersection?.contains(key) == true)
    }

    func testCancellationBeforeCandidateGeneration() {
        let token = CancellationToken()
        token.cancel()
        XCTAssertThrowsError(try NestedRecoverySession.calibratedCandidates(plaintext: 0, encrypted: 0, uid: 0, token: token))
    }
}
