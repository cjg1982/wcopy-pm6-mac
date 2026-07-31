import Foundation

/// Crypto1 stream cipher primitives for MIFARE Classic.
///
/// This is an original Swift implementation of the published Crypto1 cipher
/// (48-bit LFSR with the 20-bit filter function and the 16-bit nonce PRNG), the
/// odd/even split state representation, and the LFSR-state recovery/rollback
/// helpers used by nested-authentication key recovery. Behavior is pinned to the
/// reference implementation semantics by protocol tests using generated vectors.
enum Crypto1 {
    // LFSR feedback polynomials for the odd/even split representation.
    static let lfsrPolyOdd: UInt32  = 0x29CE5C
    static let lfsrPolyEven: UInt32 = 0x870804

    // MARK: - Filter function

    private static var filterTable: [UInt8] = {
        var table = [UInt8](repeating: 0, count: 1 << 20)
        for i in 0 ..< (1 << 20) {
            table[i] = filterRaw(UInt32(i))
        }
        return table
    }()

    static func filter(_ x: UInt32) -> UInt8 {
        filterTable[Int(x & 0xFFFFF)]
    }

    private static func filterRaw(_ x: UInt32) -> UInt8 {
        var f: UInt32 = 0
        f |= (0xF22C0 >> (x & 0xF)) & 16
        f |= (0x6C9C0 >> ((x >> 4) & 0xF)) & 8
        f |= (0x3C8B0 >> ((x >> 8) & 0xF)) & 4
        f |= (0x1E458 >> ((x >> 12) & 0xF)) & 2
        f |= (0x0D938 >> ((x >> 16) & 0xF)) & 1
        return UInt8((0xEC57E80A >> f) & 1)
    }

    // MARK: - Parity

    /// 1 if `x` has an odd number of set bits.
    static func parity(_ x: UInt32) -> UInt8 {
        var y = x
        y ^= y >> 16
        y ^= y >> 8
        y ^= y >> 4
        return UInt8((0x6996 >> (y & 0xF)) & 1)
    }

    /// Even frame parity bit for a byte (1 when the byte has an odd bit count).
    static func evenParity8(_ x: UInt8) -> UInt8 { parity(UInt32(x)) }
    /// Odd frame parity bit for a byte (1 when the byte has an even bit count).
    static func oddParity8(_ x: UInt8) -> UInt8 { parity(UInt32(x)) ^ 1 }

    // MARK: - LFSR state

    struct State: Equatable {
        var odd: UInt32
        var even: UInt32

        var isZero: Bool { odd == 0 && even == 0 }
    }

    /// Load a 48-bit key into the odd/even LFSR split.
    static func create(key: UInt64) -> State {
        var odd: UInt32 = 0
        var even: UInt32 = 0
        var i = 47
        while i > 0 {
            odd = (odd << 1) | UInt32((key >> UInt64((i - 1) ^ 7)) & 1)
            even = (even << 1) | UInt32((key >> UInt64(i ^ 7)) & 1)
            i -= 2
        }
        return State(odd: odd, even: even)
    }

    /// Extract the 48-bit LFSR contents as a key value.
    static func getLFSR(from state: State) -> UInt64 {
        var lfsr: UInt64 = 0
        for i in stride(from: 23, through: 0, by: -1) {
            lfsr = (lfsr << 1) | UInt64((state.odd >> (i ^ 3)) & 1)
            lfsr = (lfsr << 1) | UInt64((state.even >> (i ^ 3)) & 1)
        }
        return lfsr
    }

    // MARK: - Keystream generation

    /// Advance the LFSR one bit. `input` is the plaintext bit; `isEncrypted`
    /// feeds the keystream back into the register (used when processing
    /// ciphertext). Returns the keystream bit.
    static func bit(_ s: inout State, input: UInt8, isEncrypted: Bool) -> UInt8 {
        let ret = filter(s.odd)
        var feedin = UInt32(ret) & (isEncrypted ? 1 : 0)
        feedin ^= UInt32(input & 1)
        feedin ^= UInt32(parity(s.odd & lfsrPolyOdd))
        feedin ^= UInt32(parity(s.even & lfsrPolyEven))
        s.even = (s.even << 1) | UInt32(parity(feedin))
        swap(&s.odd, &s.even)
        return ret
    }

    static func byte(_ s: inout State, input: UInt8, isEncrypted: Bool) -> UInt8 {
        var ret: UInt8 = 0
        for i in 0 ..< 8 {
            let outBit = bit(&s, input: (input >> UInt8(i)) & 1, isEncrypted: isEncrypted)
            ret |= outBit << i
        }
        return ret
    }

    static func word(_ s: inout State, input: UInt32, isEncrypted: Bool) -> UInt32 {
        var ret: UInt32 = 0
        for i in 0 ..< 32 {
            let inBit = (input >> UInt32(i ^ 24)) & 1
            let outBit = bit(&s, input: UInt8(inBit), isEncrypted: isEncrypted)
            ret |= UInt32(outBit) << UInt32(i ^ 24)
        }
        return ret
    }

    // MARK: - Rollback

    /// Step the LFSR one bit backwards. Returns the keystream bit that would
    /// have been produced when moving forward.
    static func rollbackBit(_ s: inout State, input: UInt32, fb: UInt32) -> UInt8 {
        s.odd &= 0xFFFFFF
        swap(&s.odd, &s.even)
        var out = s.even & 1
        s.even >>= 1
        out ^= UInt32(parity(s.even & lfsrPolyEven))
        out ^= UInt32(parity(s.odd & lfsrPolyOdd))
        out ^= input & 1
        let ret = filter(s.odd)
        out ^= UInt32(ret) & (fb & 1)
        s.even |= UInt32(parity(out)) << 23
        return ret
    }

    static func rollbackByte(_ s: inout State, input: UInt32, fb: UInt32) -> UInt8 {
        var ret: UInt8 = 0
        for i in stride(from: 7, through: 0, by: -1) {
            ret |= rollbackBit(&s, input: (input >> UInt32(i)) & 1, fb: fb) << UInt8(i)
        }
        return ret
    }

    static func rollbackWord(_ s: inout State, input: UInt32, fb: UInt32) -> UInt32 {
        var ret: UInt32 = 0
        for i in stride(from: 31, through: 0, by: -1) {
            let inBit = (input >> UInt32(i ^ 24)) & 1
            let outBit = rollbackBit(&s, input: inBit, fb: fb)
            ret |= UInt32(outBit) << UInt32(i ^ 24)
        }
        return ret
    }

    // MARK: - Nonce PRNG

    private static func swapEndian32(_ x: UInt32) -> UInt32 {
        let step = ((x >> 8) & 0x00FF00FF) | ((x & 0x00FF00FF) << 8)
        return (step >> 16) | (step << 16)
    }

    /// Advance the card nonce PRNG `steps` times.
    static func prngSuccessor(_ x0: UInt32, _ steps: UInt32) -> UInt32 {
        var x = swapEndian32(x0)
        if steps != 0 {
            for _ in 0 ..< steps {
                x = (x >> 1) | ((x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31)
            }
        }
        return swapEndian32(x)
    }

    private static var prngDistanceTable: [UInt16] = {
        var table = [UInt16](repeating: 0, count: 1 << 16)
        var x: UInt16 = 1
        var i: UInt16 = 1
        while i != 0 {
            table[Int((x & 0xFF) << 8 | x >> 8)] = i
            x = (x >> 1) | ((x ^ (x >> 2) ^ (x >> 3) ^ (x >> 5)) << 15)
            i &+= 1
        }
        return table
    }()

    /// Number of PRNG steps from nonce `from` to nonce `to`.
    static func nonceDistance(from: UInt32, to: UInt32) -> Int {
        let fromIndex = prngDistanceTable[Int(from >> 16)]
        let toIndex = prngDistanceTable[Int(to >> 16)]
        if fromIndex == 0 || toIndex == 0 { return 0 }
        return (65535 + Int(toIndex) - Int(fromIndex)) % 65535
    }

    /// True when the nonce satisfies the two-half distance invariant of the
    /// MIFARE Classic PRNG (high half is 16 steps behind the low half).
    static func validatePrngNonce(_ nonce: UInt32) -> Bool {
        _ = prngDistanceTable
        let hi = prngDistanceTable[Int(nonce >> 16)]
        let lo = prngDistanceTable[Int(nonce & 0xFFFF)]
        return ((65535 - Int(hi) + Int(lo)) % 65535) == 16
    }

    // MARK: - CRC-A (ISO/IEC 14443-3)

    static func crc14443A(_ data: Data) -> UInt16 {
        var crc: UInt16 = 0x6363
        for byte in data {
            var b = byte
            for _ in 0 ..< 8 {
                if ((b ^ UInt8(crc & 0xFF)) & 1) != 0 {
                    crc >>= 1
                    crc ^= 0x8408
                } else {
                    crc >>= 1
                }
                b >>= 1
            }
        }
        return crc
    }

    // MARK: - Nested-auth validation

    /// Filter candidate nonces using the recovered keystream and the three
    /// received parity bits before running the LFSR state recovery.
    static func validNonce(_ nt: UInt32, _ ntEnc: UInt32, _ ks1: UInt32, parity: [UInt8]) -> Bool {
        guard parity.count >= 3 else { return false }
        let b0 = oddParity8(UInt8((nt >> 24) & 0xFF))
            == (parity[0] ^ oddParity8(UInt8((ntEnc >> 24) & 0xFF)) ^ UInt8((ks1 >> 16) & 1))
        let b1 = oddParity8(UInt8((nt >> 16) & 0xFF))
            == (parity[1] ^ oddParity8(UInt8((ntEnc >> 16) & 0xFF)) ^ UInt8((ks1 >> 8) & 1))
        let b2 = oddParity8(UInt8((nt >> 8) & 0xFF))
            == (parity[2] ^ oddParity8(UInt8((ntEnc >> 8) & 0xFF)) ^ UInt8(ks1 & 1))
        return b0 && b1 && b2
    }

    // MARK: - LFSR state recovery

    private static func binsearch(_ arr: [UInt32], _ start: Int, _ stop: Int, _ val: UInt32) -> Int {
        var lo = start
        var hi = stop
        let target = val & 0xFF000000
        while lo != hi {
            let mid = (hi - lo) >> 1
            if arr[lo + mid] > target {
                hi = lo + mid
            } else {
                lo = lo + mid + 1
            }
        }
        return lo
    }

    private static func updateContribution(_ item: inout UInt32, _ m1: UInt32, _ m2: UInt32) {
        var p = item >> 25
        p = (p << 1) | UInt32(parity(item & m1))
        p = (p << 1) | UInt32(parity(item & m2))
        item = (p << 24) | (item & 0xFFFFFF)
    }

    /// Extend a candidate table using one keystream bit; `bit` is 0/1.
    private static func extendTable(_ table: inout [UInt32], head: Int, tail: inout Int, bit: Int, m1: UInt32, m2: UInt32, input: UInt32) {
        let inShifted = input << 24
        var idx = head
        table[idx] <<= 1
        while idx <= tail {
            let f0 = filter(table[idx])
            let f1 = filter(table[idx] | 1)
            if f0 ^ f1 != 0 {
                table[idx] |= UInt32(f0 ^ UInt8(bit))
                updateContribution(&table[idx], m1, m2)
                table[idx] ^= inShifted
            } else if f0 == UInt8(bit) {
                tail += 1
                if tail >= table.count { table.append(contentsOf: [0, 0]) }
                table[tail] = table[idx + 1]
                table[idx + 1] = table[idx] | 1
                updateContribution(&table[idx], m1, m2)
                table[idx] ^= inShifted
                idx += 1
                updateContribution(&table[idx], m1, m2)
                table[idx] ^= inShifted
            } else {
                table[idx] = table[tail]
                tail -= 1
                idx -= 1
            }
            idx += 1
            if idx <= tail { table[idx] <<= 1 }
        }
    }

    /// Simplified table extension that only filters by keystream bit.
    private static func extendTableSimple(_ table: inout [UInt32], head: Int, tail: inout Int, bit: Int) {
        var idx = head
        table[idx] <<= 1
        while idx <= tail {
            let f0 = filter(table[idx])
            let f1 = filter(table[idx] | 1)
            if f0 ^ f1 != 0 {
                table[idx] |= UInt32(f0 ^ UInt8(bit))
            } else if f0 == UInt8(bit) {
                tail += 1
                if tail >= table.count { table.append(contentsOf: [0, 0]) }
                table[tail] = table[idx + 1]
                table[idx + 1] = table[idx] | 1
                idx += 1
            } else {
                table[idx] = table[tail]
                tail -= 1
                idx -= 1
            }
            idx += 1
            if idx <= tail { table[idx] <<= 1 }
        }
    }

    private static func recover(
        oddTable: inout [UInt32], oddHead: Int, oddTailIn: Int, oks: UInt32,
        evenTable: inout [UInt32], evenHead: Int, evenTailIn: Int, eks: UInt32,
        rem: Int, input: UInt32, results: inout [State]
    ) {
        if rem == -1 {
            for eIdx in evenHead ... evenTailIn {
                evenTable[eIdx] = (evenTable[eIdx] << 1)
                    ^ UInt32(parity(evenTable[eIdx] & lfsrPolyEven))
                    ^ ((input >> 2) & 1)
                for oIdx in oddHead ... oddTailIn {
                    results.append(State(
                        odd: evenTable[eIdx] ^ UInt32(parity(oddTable[oIdx] & lfsrPolyOdd)),
                        even: oddTable[oIdx]
                    ))
                }
            }
            return
        }

        var oTail = oddTailIn
        var eTail = evenTailIn
        var oksLocal = oks
        var eksLocal = eks
        var inLocal = input
        var i = 0
        var remaining = rem
        while i < 4 {
            let run = remaining
            remaining -= 1
            guard run > 0 else { break }
            oksLocal >>= 1
            extendTable(&oddTable, head: oddHead, tail: &oTail, bit: Int(oksLocal & 1),
                        m1: lfsrPolyEven << 1 | 1, m2: lfsrPolyOdd << 1, input: 0)
            if oTail < oddHead { return }
            eksLocal >>= 1
            inLocal >>= 2
            extendTable(&evenTable, head: evenHead, tail: &eTail, bit: Int(eksLocal & 1),
                        m1: lfsrPolyOdd, m2: lfsrPolyEven << 1 | 1, input: inLocal & 3)
            if eTail < evenHead { return }
            i += 1
        }

        oddTable.replaceSubrange(oddHead ... oTail, with: oddTable[oddHead ... oTail].sorted())
        evenTable.replaceSubrange(evenHead ... eTail, with: evenTable[evenHead ... eTail].sorted())

        var oIdx = oTail
        var eIdx = eTail
        while oIdx >= oddHead && eIdx >= evenHead {
            if ((oddTable[oIdx] ^ evenTable[eIdx]) >> 24) == 0 {
                let oStop = binsearch(oddTable, oddHead, oIdx, oddTable[oIdx])
                let eStop = binsearch(evenTable, evenHead, eIdx, evenTable[eIdx])
                recover(
                    oddTable: &oddTable, oddHead: oStop, oddTailIn: oIdx, oks: oksLocal,
                    evenTable: &evenTable, evenHead: eStop, evenTailIn: eIdx, eks: eksLocal,
                    rem: remaining, input: inLocal, results: &results
                )
                oIdx = oStop - 1
                eIdx = eStop - 1
            } else if oddTable[oIdx] > evenTable[eIdx] {
                oIdx = binsearch(oddTable, oddHead, oIdx, oddTable[oIdx]) - 1
            } else {
                eIdx = binsearch(evenTable, evenHead, eIdx, evenTable[eIdx]) - 1
            }
        }
    }

    /// Recover candidate LFSR states from 32 bits of keystream and the plaintext
    /// `input` that was fed while the keystream was produced. Roll each returned
    /// state back with `rollbackWord(state, input, 0)` to obtain the pre-input
    /// LFSR contents.
    static func lfsrRecovery32(_ ks2: UInt32, input: UInt32) -> [State] {
        var oks: UInt32 = 0
        var eks: UInt32 = 0
        for i in stride(from: 31, through: 0, by: -2) {
            oks = (oks << 1) | ((ks2 >> UInt32(i ^ 24)) & 1)
        }
        for i in stride(from: 30, through: 0, by: -2) {
            eks = (eks << 1) | ((ks2 >> UInt32(i ^ 24)) & 1)
        }

        let capacity = 1 << 21
        var oddTable = [UInt32](repeating: 0, count: capacity + 4)
        var evenTable = [UInt32](repeating: 0, count: capacity + 4)
        var oddTail = -1
        var evenTail = -1

        for i in stride(from: 1 << 20, through: 0, by: -1) {
            if filter(UInt32(i)) == UInt8(oks & 1) { oddTail += 1; oddTable[oddTail] = UInt32(i) }
            if filter(UInt32(i)) == UInt8(eks & 1) { evenTail += 1; evenTable[evenTail] = UInt32(i) }
        }
        guard oddTail >= 0, evenTail >= 0 else { return [] }

        for _ in 0 ..< 4 {
            oks >>= 1
            extendTableSimple(&oddTable, head: 0, tail: &oddTail, bit: Int(oks & 1))
            if oddTail < 0 { return [] }
            eks >>= 1
            extendTableSimple(&evenTable, head: 0, tail: &evenTail, bit: Int(eks & 1))
            if evenTail < 0 { return [] }
        }

        let inShifted = ((input >> 16) & 0xFF) | (input << 16) | (input & 0xFF00)
        var results: [State] = []
        results.reserveCapacity(1 << 18)
        recover(
            oddTable: &oddTable, oddHead: 0, oddTailIn: oddTail, oks: oks,
            evenTable: &evenTable, evenHead: 0, evenTailIn: evenTail, eks: eks,
            rem: 11, input: inShifted << 1, results: &results
        )
        return results
    }
}
