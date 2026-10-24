package com.vortex.internet.vortex

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

object VortexCmd {
    const val CONNECT: Int = 0x01
    const val DATA: Int = 0x02
    const val CONNECT_OK: Int = 0x03
    const val CONNECT_FAIL: Int = 0x04
    const val CLOSE: Int = 0x05
    const val VIA_PEER: Int = 0x07
    const val ATYP_IPV4: Int = 0x01
    const val ATYP_DOMAIN: Int = 0x03
}

data class LinkEndpoint(
    val name: String,
    val serverIp: String,
    val serverPort: Int,
    val masterSecret: String,
    val peerSecret: String = "",
    val paddingMin: Int = 8,
    val paddingMax: Int = 64,
    val idleTimeoutSec: Int = 300,
    val maxPayload: Int = 32768
)

class VortexSession(
    private val link: LinkEndpoint,
    private val protect: (Socket) -> Boolean
) : AutoCloseable {
    private val sock = Socket()
    private lateinit var input: DataInputStream
    private lateinit var output: DataOutputStream
    private lateinit var upCipher: VortexCipher
    private lateinit var downCipher: VortexCipher
    private val upSeq = longArrayOf(0)
    private val downSeq = longArrayOf(0)
    private val upLock = Any()
    private val downLock = Any()
    private val alive = AtomicBoolean(true)

    fun connectTarget(host: String, port: Int): Boolean =
        connectWire(buildDomainWire(host, port))

    /** CONNECT(ATYP_IPV4) — for residual IP-only flows (e.g. after DoH). */
    fun connectIpv4(ipHostOrder: Int, port: Int): Boolean =
        connectWire(buildIpv4Wire(ipHostOrder, port))

    private fun connectWire(wire: ByteArray): Boolean {
        sock.soTimeout = link.idleTimeoutSec * 1000
        sock.tcpNoDelay = true
        // protect may return false when the VPN app is already disallowed from the TUN;
        // still connect — otherwise every upstream fails.
        protect(sock)
        sock.connect(InetSocketAddress(link.serverIp, link.serverPort), 15_000)
        input = DataInputStream(sock.getInputStream())
        output = DataOutputStream(sock.getOutputStream())

        val salt = SecureRandom().nextLong()
        val saltBuf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(salt).array()
        output.write(saltBuf)
        output.flush()

        upCipher = VortexCipher(link.masterSecret, salt)
        downCipher = VortexCipher(link.masterSecret, salt xor 0xA5A5A5A5A5A5A5A5uL.toLong())

        val ok = if (link.peerSecret.isNotEmpty()) {
            sendFrame(VortexCmd.VIA_PEER, buildViaPeer(link.peerSecret, wire))
        } else {
            sendFrame(VortexCmd.CONNECT, wire)
        }
        if (!ok) return false
        val reply = recvFrame() ?: return false
        return reply.first == VortexCmd.CONNECT_OK
    }

    fun sendData(data: ByteArray, off: Int = 0, len: Int = data.size): Boolean {
        if (!alive.get()) return false
        return sendFrame(VortexCmd.DATA, data.copyOfRange(off, off + len))
    }

    fun sendClose(): Boolean = sendFrame(VortexCmd.CLOSE, ByteArray(0))

    fun recvFrame(): Pair<Int, ByteArray>? {
        if (!alive.get()) return null
        return try {
            val lenHdr = ByteArray(2)
            input.readFully(lenHdr)
            synchronized(downLock) { downCipher.crypt(lenHdr, downSeq) }
            val bodyLen = ((lenHdr[0].toInt() and 0xff) shl 8) or (lenHdr[1].toInt() and 0xff)
            if (bodyLen < 3 || bodyLen > 65535) return null
            val body = ByteArray(bodyLen)
            input.readFully(body)
            synchronized(downLock) { downCipher.crypt(body, downSeq) }
            val cmd = body[0].toInt() and 0xff
            val dataLen = ((body[1].toInt() and 0xff) shl 8) or (body[2].toInt() and 0xff)
            if (dataLen + 3 > bodyLen || dataLen > link.maxPayload) return null
            cmd to body.copyOfRange(3, 3 + dataLen)
        } catch (_: Exception) {
            alive.set(false)
            null
        }
    }

    private fun sendFrame(cmd: Int, data: ByteArray): Boolean {
        return try {
            val padMin = link.paddingMin.coerceAtLeast(0)
            val padMax = link.paddingMax.coerceAtLeast(padMin)
            val pad = if (padMax > padMin) Random.nextInt(padMin, padMax + 1) else padMin
            val bodyLen = 1 + 2 + data.size + pad
            if (bodyLen > 65535) return false
            val body = ByteArray(bodyLen)
            body[0] = cmd.toByte()
            body[1] = ((data.size ushr 8) and 0xff).toByte()
            body[2] = (data.size and 0xff).toByte()
            System.arraycopy(data, 0, body, 3, data.size)
            if (pad > 0) {
                val p = ByteArray(pad)
                SecureRandom().nextBytes(p)
                System.arraycopy(p, 0, body, 3 + data.size, pad)
            }

            val lenHdr = byteArrayOf(
                ((bodyLen ushr 8) and 0xff).toByte(),
                (bodyLen and 0xff).toByte()
            )
            synchronized(upLock) {
                upCipher.crypt(lenHdr, upSeq)
                upCipher.crypt(body, upSeq)
                output.write(lenHdr)
                output.write(body)
                output.flush()
            }
            true
        } catch (_: Exception) {
            alive.set(false)
            false
        }
    }

    override fun close() {
        alive.set(false)
        try { sendClose() } catch (_: Exception) {}
        try { sock.close() } catch (_: Exception) {}
    }

    companion object {
        fun buildDomainWire(host: String, port: Int): ByteArray {
            val hb = host.toByteArray(Charsets.US_ASCII)
            require(hb.isNotEmpty() && hb.size <= 255)
            val out = ByteArray(1 + 1 + hb.size + 2)
            out[0] = VortexCmd.ATYP_DOMAIN.toByte()
            out[1] = hb.size.toByte()
            System.arraycopy(hb, 0, out, 2, hb.size)
            out[2 + hb.size] = ((port ushr 8) and 0xff).toByte()
            out[3 + hb.size] = (port and 0xff).toByte()
            return out
        }

        fun buildIpv4Wire(ipHostOrder: Int, port: Int): ByteArray {
            val out = ByteArray(1 + 4 + 2)
            out[0] = VortexCmd.ATYP_IPV4.toByte()
            out[1] = ((ipHostOrder ushr 24) and 0xff).toByte()
            out[2] = ((ipHostOrder ushr 16) and 0xff).toByte()
            out[3] = ((ipHostOrder ushr 8) and 0xff).toByte()
            out[4] = (ipHostOrder and 0xff).toByte()
            out[5] = ((port ushr 8) and 0xff).toByte()
            out[6] = (port and 0xff).toByte()
            return out
        }

        fun buildViaPeer(secret: String, targetWire: ByteArray): ByteArray {
            val sb = secret.toByteArray(Charsets.UTF_8)
            require(sb.isNotEmpty() && sb.size <= 255)
            return byteArrayOf(sb.size.toByte()) + sb + targetWire
        }
    }
}
