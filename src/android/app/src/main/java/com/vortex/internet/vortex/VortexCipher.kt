package com.vortex.internet.vortex

/**
 * Port of include/vortex_cipher.hpp — ARX stream cipher used by Vortex frames.
 */
class VortexCipher(key: String, salt: Long) {
    private val state = IntArray(4)

    init {
        state[0] = 0x61707865.toInt()
        state[1] = 0x3320646e
        state[2] = 0x79627465
        state[3] = (salt.toInt()) xor 0x9e3779b9.toInt()
        state[0] = state[0] xor (salt ushr 32).toInt()
        for (i in key.indices) {
            val b = key[i].code and 0xff
            state[i % 4] = state[i % 4] xor (b shl ((i % 4) * 8))
        }
    }

    private fun rotl(v: Int, s: Int): Int = (v shl s) or (v ushr (32 - s))

    private fun quarterRound(w: IntArray, a: Int, b: Int, c: Int, d: Int) {
        w[a] = w[a] + w[b]; w[d] = rotl(w[d] xor w[a], 16)
        w[c] = w[c] + w[d]; w[b] = rotl(w[b] xor w[c], 12)
        w[a] = w[a] + w[b]; w[d] = rotl(w[d] xor w[a], 8)
        w[c] = w[c] + w[d]; w[b] = rotl(w[b] xor w[c], 7)
    }

    private fun generateBlock(counter: Long): ByteArray {
        val working = intArrayOf(
            state[0],
            state[1],
            state[2],
            state[3] xor counter.toInt() xor (counter ushr 32).toInt()
        )
        repeat(8) { quarterRound(working, 0, 1, 2, 3) }
        working[0] += state[0]
        working[1] += state[1]
        working[2] += state[2]
        working[3] += state[3] xor counter.toInt()
        val out = ByteArray(16)
        for (i in 0 until 4) {
            val v = working[i]
            out[i * 4] = (v and 0xff).toByte()
            out[i * 4 + 1] = ((v ushr 8) and 0xff).toByte()
            out[i * 4 + 2] = ((v ushr 16) and 0xff).toByte()
            out[i * 4 + 3] = ((v ushr 24) and 0xff).toByte()
        }
        return out
    }

    /** In-place XOR; [packetSeq] is advanced like the C++ reference. */
    fun crypt(data: ByteArray, offset: Int, len: Int, packetSeq: LongArray) {
        var seq = packetSeq[0]
        var stream = ByteArray(0)
        for (i in 0 until len) {
            if (i % 16 == 0) {
                stream = generateBlock(seq++)
            }
            data[offset + i] = (data[offset + i].toInt() xor (stream[i % 16].toInt() and 0xff)).toByte()
        }
        packetSeq[0] = seq
    }

    fun crypt(data: ByteArray, packetSeq: LongArray) = crypt(data, 0, data.size, packetSeq)
}
