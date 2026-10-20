import Foundation
import XCTest
@testable import WCopyNFCMac

final class PM6RecoveryTests: XCTestCase {
    func testConfiguredPM6SkipsOnlyRedundantSAMConfig() throws {
        let target = CardTarget(uid: Data([1,2,3,4]), atqa: 4, sak: 8, kind: .classic1K)
        for required in [true, false] {
            let spy = RecoveryConfigurationSpy(required)
            try NestedRecoverySession(transport: spy, target: target, logger: { _ in }).configureForAuth()
            XCTAssertEqual(spy.commands.contains(0x14), required)
            XCTAssertEqual(Array(spy.commands.suffix(3)), [0x32, 0x32, 0x4A])
            XCTAssertTrue(spy.writtenRegisters.contains(0x633D))
        }
    }
}

private final class RecoveryConfigurationSpy: NestedRecoveryTransport {
    let requiresSAMConfiguration: Bool
    var commands: [UInt8] = []
    var writtenRegisters: Set<UInt16> = []
    init(_ required: Bool) { requiresSAMConfiguration = required }
    func rawPN532(_ bytes: Data) throws -> Data {
        commands.append(bytes[1])
        if bytes[1] == 0x4A { return Data([0xD5,0x4B,1,1,0,4,8,4,1,2,3,4]) }
        return Data([0xD5,bytes[1] &+ 1,0])
    }
    func readRegister(_ address: UInt16) throws -> UInt8 { 0 }
    func writeRegister(_ address: UInt16, value: UInt8) throws { writtenRegisters.insert(address) }
    func transceiveRawBits(data: Data, parity: [UInt8], timeout: TimeInterval) throws -> (data: Data, parity: [UInt8]) { (data,parity) }
    func authenticate(block: Int, uid: Data, key: Data, type: KeyType) throws -> Bool { true }
    func readBlock(_ block: Int) throws -> Data? { nil }
}
