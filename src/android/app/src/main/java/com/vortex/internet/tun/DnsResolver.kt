package com.vortex.internet.tun

import android.net.VpnService
import com.vortex.internet.rules.RulesEngine
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * resolve_ipv4_fast from internet.cpp:
 * UDP → client resolver / 8.8.8.8 / 1.1.1.1, then DNS-over-TCP (protect),
 * then optional SOCKS/Vortex DNS-over-TCP fallback (resolve_ipv4_via_socks).
 */
class DnsResolver(
    private val vpn: VpnService,
    private val protect: (Any) -> Unit,
    /** Optional: DNS-over-TCP via MultiLink (8.8.8.8:53), like resolve_ipv4_via_socks. */
    private val viaProxyDnsTcp: ((String) -> Int?)? = null
) {
    enum class Result { Ok, NoData, Fail }

    fun resolveIpv4Fast(name: String, clientResolverHostOrder: Int): Int? {
        val qname = name.trim('.').lowercase()
        if (qname.isEmpty() || qname.length > 253) return null
        if (RulesEngine.isDottedIpv4(qname)) {
            val ip = RulesEngine.ipv4FromDotted(qname) ?: return null
            return if (!DnsBinder.isPrivateIpDivert(ip)) ip else null
        }

        var out = 0
        fun tryUdp(resolver: Int, timeoutMs: Int): Result {
            if (resolver == 0) return Result.Fail
            return resolveUdp(qname, resolver, timeoutMs).also { r ->
                if (r.first == Result.Ok) out = r.second
            }.first
        }

        var r = tryUdp(clientResolverHostOrder, 600)
        if (r == Result.Ok) return out
        if (r == Result.NoData) return null

        val r88 = 0x08080808
        val r1111 = 0x01010101
        if (clientResolverHostOrder != r88) {
            r = tryUdp(r88, 600)
            if (r == Result.Ok) return out
            if (r == Result.NoData) return null
        }
        if (clientResolverHostOrder != r1111) {
            r = tryUdp(r1111, 600)
            if (r == Result.Ok) return out
            if (r == Result.NoData) return null
        }

        // Clean path: protect DNS-over-TCP (internet.cpp resolve_ipv4_dns_tcp).
        resolveTcp(qname, r88)?.let { return it }
        resolveTcp(qname, r1111)?.let { return it }

        // Via MultiLink (internet.cpp resolve_ipv4_via_socks).
        viaProxyDnsTcp?.invoke(qname)?.let { return it }
        return null
    }

    private fun buildQueryA(name: String, id: Int): ByteArray {
        val q = ArrayList<Byte>(64)
        q += ((id ushr 8) and 0xff).toByte()
        q += (id and 0xff).toByte()
        q += 1; q += 0
        q += 0; q += 1
        q += 0; q += 0; q += 0; q += 0; q += 0; q += 0
        for (lab in name.split('.')) {
            val b = lab.toByteArray(Charsets.US_ASCII)
            if (b.isEmpty() || b.size > 63) return ByteArray(0)
            q += b.size.toByte()
            b.forEach { q += it }
        }
        q += 0
        q += 0; q += 1
        q += 0; q += 1
        return q.toByteArray()
    }

    private fun resolveUdp(name: String, resolverHostOrder: Int, timeoutMs: Int): Pair<Result, Int> {
        val query = buildQueryA(name, (System.nanoTime() and 0xffff).toInt())
        if (query.isEmpty()) return Result.Fail to 0
        val ds = DatagramSocket()
        try {
            protect(ds)
            ds.soTimeout = timeoutMs
            val addr = InetAddress.getByAddress(intToBytes(resolverHostOrder))
            ds.send(DatagramPacket(query, query.size, addr, 53))
            val buf = ByteArray(2048)
            val pkt = DatagramPacket(buf, buf.size)
            ds.receive(pkt)
            return parseDnsA(buf, pkt.length)
        } catch (_: Exception) {
            return Result.Fail to 0
        } finally {
            try { ds.close() } catch (_: Exception) {}
        }
    }

    private fun resolveTcp(name: String, resolverHostOrder: Int): Int? {
        val query = buildQueryA(name, (System.nanoTime() and 0xffff).toInt())
        if (query.isEmpty()) return null
        val s = Socket()
        try {
            protect(s)
            s.soTimeout = 5000
            s.connect(InetSocketAddress(InetAddress.getByAddress(intToBytes(resolverHostOrder)), 53), 5000)
            return dnsTcpTransact(s, query)
        } catch (_: Exception) {
            return null
        } finally {
            try { s.close() } catch (_: Exception) {}
        }
    }

    fun dnsTcpTransact(s: Socket, query: ByteArray): Int? {
        val out = DataOutputStream(s.getOutputStream())
        out.writeShort(query.size)
        out.write(query)
        out.flush()
        val inp = DataInputStream(s.getInputStream())
        val respLen = inp.readUnsignedShort()
        if (respLen < 12 || respLen > 4096) return null
        val resp = ByteArray(respLen)
        inp.readFully(resp)
        val (r, ip) = parseDnsA(resp, resp.size)
        return if (r == Result.Ok) ip else null
    }

    fun buildQueryAPublic(name: String): ByteArray =
        buildQueryA(name.trim('.').lowercase(), (System.nanoTime() and 0xffff).toInt())

    fun parseDnsA(resp: ByteArray, rlen: Int): Pair<Result, Int> {
        if (rlen < 12) return Result.Fail to 0
        val rcode = resp[3].toInt() and 0x0f
        if (rcode == 3) return Result.NoData to 0
        if (rcode != 0) return Result.Fail to 0
        val ancount = ((resp[6].toInt() and 0xff) shl 8) or (resp[7].toInt() and 0xff)
        var off = skipName(resp, rlen, 12)
        if (off + 4 > rlen) return Result.Fail to 0
        off += 4
        var saw = false
        repeat(ancount) {
            if (off + 10 > rlen) return@repeat
            off = skipName(resp, rlen, off)
            if (off + 10 > rlen) return Result.Fail to 0
            val typ = ((resp[off].toInt() and 0xff) shl 8) or (resp[off + 1].toInt() and 0xff)
            val rdlen = ((resp[off + 8].toInt() and 0xff) shl 8) or (resp[off + 9].toInt() and 0xff)
            off += 10
            if (off + rdlen > rlen) return Result.Fail to 0
            saw = true
            if (typ == 1 && rdlen == 4) {
                val ip = PacketUtil.readInt(resp, off)
                if (ip != 0 && !DnsBinder.isPrivateIpDivert(ip)) return Result.Ok to ip
            }
            off += rdlen
        }
        return if (saw || ancount == 0) Result.NoData to 0 else Result.Fail to 0
    }

    private fun skipName(msg: ByteArray, len: Int, start: Int): Int {
        var off = start
        var hops = 0
        while (off < len && hops < 64) {
            val lab = msg[off].toInt() and 0xff
            if (lab == 0) return off + 1
            if (lab and 0xc0 == 0xc0) return if (off + 2 < len) off + 2 else len
            if (off + 1 + lab > len) return len
            off += 1 + lab
            hops++
        }
        return len
    }

    private fun intToBytes(hostOrder: Int): ByteArray = byteArrayOf(
        ((hostOrder ushr 24) and 0xff).toByte(),
        ((hostOrder ushr 16) and 0xff).toByte(),
        ((hostOrder ushr 8) and 0xff).toByte(),
        (hostOrder and 0xff).toByte()
    )
}
