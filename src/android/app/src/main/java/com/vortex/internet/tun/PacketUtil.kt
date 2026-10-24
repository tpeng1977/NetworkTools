package com.vortex.internet.tun

object PacketUtil {
    const val TCP_SYN = 0x02
    const val TCP_ACK = 0x10
    const val TCP_FIN = 0x01
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08

    data class Ipv4L4(
        val src: Int, // network order as int (big-endian bits)
        val dst: Int,
        val sport: Int,
        val dport: Int,
        val proto: Int,
        val tcpFlags: Int,
        val seq: Long,
        val ack: Long,
        val payload: ByteArray,
        val ipHeaderLen: Int,
        val tcpHeaderLen: Int
    )

    fun parseIpv4(packet: ByteArray, len: Int): Ipv4L4? {
        if (len < 20) return null
        val verIhl = packet[0].toInt() and 0xff
        if (verIhl ushr 4 != 4) return null
        val ihl = (verIhl and 0x0f) * 4
        if (ihl < 20 || len < ihl) return null
        val totalLenHdr = ((packet[2].toInt() and 0xff) shl 8) or (packet[3].toInt() and 0xff)
        // Some OEM stacks report padded read sizes; prefer header length when sane.
        val totalLen = when {
            totalLenHdr in (ihl + 1)..len -> totalLenHdr
            else -> len
        }
        val frag = ((packet[6].toInt() and 0xff) shl 8) or (packet[7].toInt() and 0xff)
        if (frag and 0x3fff != 0) return null // fragmented
        val proto = packet[9].toInt() and 0xff
        val src = readInt(packet, 12)
        val dst = readInt(packet, 16)
        if (proto == 17) { // UDP
            if (totalLen < ihl + 8) return null
            val sport = ((packet[ihl].toInt() and 0xff) shl 8) or (packet[ihl + 1].toInt() and 0xff)
            val dport = ((packet[ihl + 2].toInt() and 0xff) shl 8) or (packet[ihl + 3].toInt() and 0xff)
            val payload = packet.copyOfRange(ihl + 8, totalLen)
            return Ipv4L4(src, dst, sport, dport, 17, 0, 0, 0, payload, ihl, 8)
        }
        if (proto == 6) { // TCP
            if (totalLen < ihl + 20) return null
            val sport = ((packet[ihl].toInt() and 0xff) shl 8) or (packet[ihl + 1].toInt() and 0xff)
            val dport = ((packet[ihl + 2].toInt() and 0xff) shl 8) or (packet[ihl + 3].toInt() and 0xff)
            val seq = readInt(packet, ihl + 4).toLong() and 0xffffffffL
            val ack = readInt(packet, ihl + 8).toLong() and 0xffffffffL
            val dataOff = ((packet[ihl + 12].toInt() and 0xff) ushr 4) * 4
            if (dataOff < 20 || ihl + dataOff > totalLen) return null
            val flags = packet[ihl + 13].toInt() and 0xff
            val payload = packet.copyOfRange(ihl + dataOff, totalLen)
            return Ipv4L4(src, dst, sport, dport, 6, flags, seq, ack, payload, ihl, dataOff)
        }
        return null
    }

    fun readInt(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 24) or
            ((b[off + 1].toInt() and 0xff) shl 16) or
            ((b[off + 2].toInt() and 0xff) shl 8) or
            (b[off + 3].toInt() and 0xff)

    fun writeInt(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v ushr 24) and 0xff).toByte()
        b[off + 1] = ((v ushr 16) and 0xff).toByte()
        b[off + 2] = ((v ushr 8) and 0xff).toByte()
        b[off + 3] = (v and 0xff).toByte()
    }

    fun ipChecksum(header: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = 0
        while (i < len) {
            val word = if (i + 1 < len) {
                ((header[off + i].toInt() and 0xff) shl 8) or (header[off + i + 1].toInt() and 0xff)
            } else {
                (header[off + i].toInt() and 0xff) shl 8
            }
            sum += word
            i += 2
        }
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return (sum.inv() and 0xffff).toInt()
    }

    /** DNS reply: [src:sport] = resolver side, [dst:dport] = client (same as desktop inject). */
    fun buildUdpDnsReply(
        src: Int, sport: Int, dst: Int, dport: Int,
        query: ByteArray, answerIpHost: Int, ttl: Int = 300
    ): ByteArray {
        // Build DNS answer: copy query ID/flags/qd, set QR+AA, add one A record.
        if (query.size < 12) return ByteArray(0)
        val nameEnd = skipDnsName(query, 12)
        if (nameEnd + 4 > query.size) return ByteArray(0)
        val qname = query.copyOfRange(12, nameEnd + 5) // name\0 + type + class

        val dns = ArrayList<Byte>()
        dns += query[0]; dns += query[1] // id
        dns += 0x81.toByte(); dns += 0x80.toByte() // QR AA RD RA
        dns += 0; dns += 1 // qd
        dns += 0; dns += 1 // an
        dns += 0; dns += 0; dns += 0; dns += 0
        qname.forEach { dns += it }
        // answer: pointer to name at 12
        dns += 0xc0.toByte(); dns += 0x0c.toByte()
        dns += 0; dns += 1 // A
        dns += 0; dns += 1 // IN
        dns += ((ttl ushr 24) and 0xff).toByte()
        dns += ((ttl ushr 16) and 0xff).toByte()
        dns += ((ttl ushr 8) and 0xff).toByte()
        dns += (ttl and 0xff).toByte()
        dns += 0; dns += 4
        dns += ((answerIpHost ushr 24) and 0xff).toByte()
        dns += ((answerIpHost ushr 16) and 0xff).toByte()
        dns += ((answerIpHost ushr 8) and 0xff).toByte()
        dns += (answerIpHost and 0xff).toByte()

        return buildUdpPacket(src, sport, dst, dport, dns.toByteArray())
    }

    /** NODATA (like internet.cpp dns_reply_nodata) — for AAAA etc. so stacks use IPv4. */
    fun buildUdpDnsNodata(
        src: Int, sport: Int, dst: Int, dport: Int, query: ByteArray
    ): ByteArray = buildUdpDnsFlags(src, sport, dst, dport, query, rcode = 0)

    /** SERVFAIL (internet.cpp dns_reply_servfail). */
    fun buildUdpDnsServfail(
        src: Int, sport: Int, dst: Int, dport: Int, query: ByteArray
    ): ByteArray = buildUdpDnsFlags(src, sport, dst, dport, query, rcode = 2)

    private fun buildUdpDnsFlags(
        src: Int, sport: Int, dst: Int, dport: Int, query: ByteArray, rcode: Int
    ): ByteArray {
        if (query.size < 12) return ByteArray(0)
        val nameEnd = skipDnsName(query, 12)
        if (nameEnd + 4 > query.size) return ByteArray(0)
        val qEnd = nameEnd + 5 // after type+class
        val dns = query.copyOfRange(0, qEnd)
        dns[2] = ((dns[2].toInt() and 0x01) or 0x80).toByte()
        dns[3] = ((dns[3].toInt() and 0xf0) or (rcode and 0x0f)).toByte()
        if (rcode == 0) dns[3] = 0x80.toByte() // AA + RA like desktop NODATA
        dns[4] = 0; dns[5] = 1
        dns[6] = 0; dns[7] = 0
        dns[8] = 0; dns[9] = 0
        dns[10] = 0; dns[11] = 0
        return buildUdpPacket(src, sport, dst, dport, dns)
    }

    /** Returns index of terminating 0, or last byte of compression pointer. */
    private fun skipDnsName(msg: ByteArray, start: Int): Int {
        var off = start
        var hops = 0
        while (off < msg.size && hops < 64) {
            val lab = msg[off].toInt() and 0xff
            if (lab == 0) return off
            // Compression pointer: 2 bytes (align with internet.cpp dns_skip_name).
            if (lab and 0xc0 == 0xc0) return if (off + 1 < msg.size) off + 1 else msg.size - 1
            off += 1 + lab
            hops++
        }
        return msg.size
    }

    fun dnsQname(query: ByteArray): String {
        if (query.size < 12) return ""
        var off = 12
        val parts = ArrayList<String>()
        var hops = 0
        while (off < query.size && hops < 64) {
            val lab = query[off].toInt() and 0xff
            if (lab == 0) break
            if (lab and 0xc0 == 0xc0 || off + 1 + lab > query.size) return ""
            parts += String(query, off + 1, lab, Charsets.US_ASCII)
            off += 1 + lab
            hops++
        }
        return parts.joinToString(".").lowercase()
    }

    /** DNS QTYPE after QNAME (1=A, 28=AAAA). */
    fun dnsQtype(query: ByteArray): Int {
        if (query.size < 12) return 0
        val nameEnd = skipDnsName(query, 12)
        if (nameEnd + 4 > query.size) return 0
        return ((query[nameEnd + 1].toInt() and 0xff) shl 8) or
            (query[nameEnd + 2].toInt() and 0xff)
    }

    fun buildUdpPacket(src: Int, sport: Int, dst: Int, dport: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        pkt[2] = ((total ushr 8) and 0xff).toByte()
        pkt[3] = (total and 0xff).toByte()
        pkt[8] = 64 // ttl
        pkt[9] = 17
        writeInt(pkt, 12, src)
        writeInt(pkt, 16, dst)
        val ipCsum = ipChecksum(pkt, 0, 20)
        pkt[10] = ((ipCsum ushr 8) and 0xff).toByte()
        pkt[11] = (ipCsum and 0xff).toByte()

        pkt[20] = ((sport ushr 8) and 0xff).toByte()
        pkt[21] = (sport and 0xff).toByte()
        pkt[22] = ((dport ushr 8) and 0xff).toByte()
        pkt[23] = (dport and 0xff).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xff).toByte()
        pkt[25] = (udpLen and 0xff).toByte()
        // checksum field 26-27 left 0 while computing
        System.arraycopy(payload, 0, pkt, 28, payload.size)
        // TUN-injected packets are CHECKSUM_NONE — zero UDP csum is often dropped on Android.
        val udpCsum = udpChecksum(pkt, src, dst, udpLen)
        pkt[26] = ((udpCsum ushr 8) and 0xff).toByte()
        pkt[27] = (udpCsum and 0xff).toByte()
        return pkt
    }

    private fun udpChecksum(pkt: ByteArray, src: Int, dst: Int, udpLen: Int): Int {
        var sum = 0L
        sum += (src ushr 16) and 0xffff
        sum += src and 0xffff
        sum += (dst ushr 16) and 0xffff
        sum += dst and 0xffff
        sum += 17
        sum += udpLen
        var i = 20
        val end = 20 + udpLen
        while (i < end) {
            val word = if (i + 1 < end) {
                ((pkt[i].toInt() and 0xff) shl 8) or (pkt[i + 1].toInt() and 0xff)
            } else {
                (pkt[i].toInt() and 0xff) shl 8
            }
            sum += word
            i += 2
        }
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        var c = (sum.inv() and 0xffff).toInt()
        if (c == 0) c = 0xffff // UDP checksum 0 means "none"; never emit that after computing
        return c
    }

    fun ipToString(hostOrder: Int): String =
        "${(hostOrder ushr 24) and 0xff}.${(hostOrder ushr 16) and 0xff}." +
            "${(hostOrder ushr 8) and 0xff}.${hostOrder and 0xff}"

    fun buildTcpPacket(
        src: Int, sport: Int, dst: Int, dport: Int,
        seq: Long, ack: Long, flags: Int, payload: ByteArray, mss: Int = 1200
    ): ByteArray {
        val optLen = if ((flags and TCP_SYN) != 0) 4 else 0
        val tcpHdr = 20 + optLen
        val total = 20 + tcpHdr + payload.size
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        pkt[2] = ((total ushr 8) and 0xff).toByte()
        pkt[3] = (total and 0xff).toByte()
        pkt[8] = 64
        pkt[9] = 6
        writeInt(pkt, 12, src)
        writeInt(pkt, 16, dst)
        val ipCsum = ipChecksum(pkt, 0, 20)
        pkt[10] = ((ipCsum ushr 8) and 0xff).toByte()
        pkt[11] = (ipCsum and 0xff).toByte()

        val t = 20
        pkt[t] = ((sport ushr 8) and 0xff).toByte()
        pkt[t + 1] = (sport and 0xff).toByte()
        pkt[t + 2] = ((dport ushr 8) and 0xff).toByte()
        pkt[t + 3] = (dport and 0xff).toByte()
        writeInt(pkt, t + 4, seq.toInt())
        writeInt(pkt, t + 8, ack.toInt())
        pkt[t + 12] = (((tcpHdr / 4) shl 4) and 0xf0).toByte()
        pkt[t + 13] = (flags and 0xff).toByte()
        pkt[t + 14] = 0xff.toByte(); pkt[t + 15] = 0xff.toByte() // window
        if (optLen == 4) {
            pkt[t + 20] = 2; pkt[t + 21] = 4
            pkt[t + 22] = ((mss ushr 8) and 0xff).toByte()
            pkt[t + 23] = (mss and 0xff).toByte()
        }
        System.arraycopy(payload, 0, pkt, 20 + tcpHdr, payload.size)

        // TCP checksum with pseudo header
        val csum = tcpChecksum(pkt, src, dst, tcpHdr + payload.size)
        pkt[t + 16] = ((csum ushr 8) and 0xff).toByte()
        pkt[t + 17] = (csum and 0xff).toByte()
        return pkt
    }

    private fun tcpChecksum(pkt: ByteArray, src: Int, dst: Int, tcpLen: Int): Int {
        var sum = 0L
        sum += (src ushr 16) and 0xffff
        sum += src and 0xffff
        sum += (dst ushr 16) and 0xffff
        sum += dst and 0xffff
        sum += 6
        sum += tcpLen
        var i = 20
        val end = 20 + tcpLen
        while (i < end) {
            val word = if (i + 1 < end) {
                ((pkt[i].toInt() and 0xff) shl 8) or (pkt[i + 1].toInt() and 0xff)
            } else {
                (pkt[i].toInt() and 0xff) shl 8
            }
            sum += word
            i += 2
        }
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return (sum.inv() and 0xffff).toInt()
    }

    fun hostOrderIp(netOrder: Int): Int {
        // our readInt already stores as big-endian numeric (host view of dotted IP)
        return netOrder
    }

    /**
     * Next host in 198.18.0.0/15 (internet.cpp kStandInHostMin..Max),
     * skipping .0 / .255 host octets.
     */
    fun nextStandIn(counter: AtomicCounter): Int {
        while (true) {
            val host = counter.next()
            val b3 = host and 0xff
            if (b3 == 0 || b3 == 255) continue
            return host
        }
    }

    /** Mutable stand-in allocator state (0xC6120001 .. 0xC613FFFE). */
    class AtomicCounter {
        private val min = 0xC6120001.toInt()
        private val max = 0xC613FFFE.toInt()
        private val v = java.util.concurrent.atomic.AtomicInteger(min)
        fun next(): Int {
            while (true) {
                val cur = v.get()
                // Compare as unsigned host values in 198.18/15.
                val nextHost = if (cur == max) min else cur + 1
                if (v.compareAndSet(cur, nextHost)) return cur
            }
        }
    }
}
