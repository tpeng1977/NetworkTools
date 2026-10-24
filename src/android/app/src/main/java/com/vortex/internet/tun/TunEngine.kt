package com.vortex.internet.tun

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.Os
import android.util.Log
import com.vortex.internet.config.InternetConfig
import com.vortex.internet.rules.Action
import com.vortex.internet.rules.RulesEngine
import com.vortex.internet.vortex.VortexCmd
import com.vortex.internet.vortex.VortexSession
import java.io.FileDescriptor
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Redir-host + MultiLink aligned with desktop internet.cpp:
 *
 * 1) Own egress — addDisallowedApplication + protect (WinDivert own-socket).
 * 2) DNS UDP/53 — resolve_ipv4_fast + dns_bind_name; AAAA NODATA; SERVFAIL on fail.
 * 3) TCP to learned IP — CONNECT(domain) / DIRECT (rules), never CONNECT(IP).
 * 4) Unknown TCP — protected IP passthrough (VpnService substitute for reinject).
 * 5) QUIC/DoT — drop.
 */
class TunEngine(
    private val vpn: VpnService,
    private val tun: ParcelFileDescriptor,
    private val config: InternetConfig,
    private val log: (String) -> Unit
) {
    private val running = AtomicBoolean(true)
    private val rules = RulesEngine(config.rulesYaml, config.geoipCn, config.geositeCn)
    private val dns = DnsBinder()
    private val resolver: DnsResolver
    private val flows = ConcurrentHashMap<FlowKey, TcpFlow>()
    private val pool = Executors.newCachedThreadPool()
    private val outLock = Any()
    private val tunFd: FileDescriptor = tun.fileDescriptor
    private val dnsLogLeft = AtomicInteger(40)
    private val dnsInflight = AtomicInteger(0)
    private val pktIn = AtomicInteger(0)
    private val dnsIn = AtomicInteger(0)
    private val dnsOut = AtomicInteger(0)
    private val parseFail = AtomicInteger(0)

    init {
        resolver = DnsResolver(vpn, ::protectAny, ::resolveViaProxyDnsTcp)
    }

    private data class FlowKey(val src: Int, val dst: Int, val sport: Int, val dport: Int)

    private class TcpFlow(
        val key: FlowKey,
        val host: String,
        val learned: Boolean,
        @Volatile var clientNext: Long,
        @Volatile var serverSeq: Long,
        @Volatile var serverAck: Long,
        var session: VortexSession? = null,
        var direct: Socket? = null,
        @Volatile var alive: Boolean = true,
        @Volatile var upstreamReady: Boolean = false,
        @Volatile var lastActiveMs: Long = System.currentTimeMillis(),
        val pendingLock: Any = Any(),
        val pending: ArrayList<ByteArray> = ArrayList()
    )

    fun start() {
        thread(name = "tun-reader", isDaemon = true) { readerLoop() }
        thread(name = "tun-idle", isDaemon = true) { idleLoop() }
        log(
            "TunEngine redir-host links=${config.links.size} default=${config.defaultLink} " +
                "geoip=${rules.cnCidrCount} geosite=${rules.cnDomainCount} " +
                "maxConn=${config.maxConnections} dnsInf=${config.maxDnsInflight}"
        )
        log("对齐 internet.cpp: protect 自排除 · DNS redir-host · learned TCP→CONNECT(domain)")
    }

    fun stop() {
        running.set(false)
        flows.values.forEach { closeFlow(it) }
        flows.clear()
        pool.shutdownNow()
        try { tun.close() } catch (_: Exception) {}
    }

    private fun protectAny(sock: Any) {
        try {
            when (sock) {
                is Socket -> vpn.protect(sock)
                is DatagramSocket -> vpn.protect(sock)
            }
        } catch (_: Exception) {
        }
    }

    private fun idleLoop() {
        val idleMs = config.divertIdleTimeoutSec.toLong() * 1000L
        while (running.get()) {
            try {
                Thread.sleep(5000)
            } catch (_: InterruptedException) {
                break
            }
            val now = System.currentTimeMillis()
            for ((key, flow) in flows) {
                if (!flow.alive) continue
                if (now - flow.lastActiveMs > idleMs) {
                    log("idle timeout ${flow.host}:${flow.key.dport}")
                    sendRst(flow)
                    closeFlow(flow)
                    flows.remove(key)
                }
            }
        }
    }

    private fun readerLoop() {
        val buf = ByteArray(32767)
        while (running.get()) {
            val n = try {
                Os.read(tunFd, buf, 0, buf.size)
            } catch (e: Exception) {
                if (running.get()) log("tun read: ${e.message}")
                break
            }
            if (n <= 0) continue
            pktIn.incrementAndGet()
            try {
                onPacket(buf, n)
            } catch (e: Exception) {
                Log.w(TAG, "packet", e)
            }
        }
        log("tun reader exit pkts=${pktIn.get()} dnsIn=${dnsIn.get()} dnsOut=${dnsOut.get()} parseFail=${parseFail.get()}")
    }

    private fun writeTun(packet: ByteArray) {
        synchronized(outLock) {
            try {
                var off = 0
                while (off < packet.size) {
                    val w = Os.write(tunFd, packet, off, packet.size - off)
                    if (w <= 0) break
                    off += w
                }
            } catch (e: Exception) {
                Log.w(TAG, "tun write", e)
            }
        }
    }

    private fun onPacket(buf: ByteArray, len: Int) {
        val v = PacketUtil.parseIpv4(buf, len)
        if (v == null) {
            parseFail.incrementAndGet()
            return
        }
        if (v.proto == 17 && v.dport == 53) {
            handleDns(v)
            return
        }
        // Drop QUIC (UDP/443) and DoT (UDP/TCP 853) so stacks fall back to
        // plain DNS:53 + TCP — same as internet.cpp on_packet.
        if (v.proto == 17 && (v.dport == 443 || v.dport == 853)) return
        if (v.proto == 6 && v.dport == 853) return
        if (v.proto == 6) handleTcp(v)
    }

    private fun handleDns(v: PacketUtil.Ipv4L4) {
        dnsIn.incrementAndGet()
        val qtype = PacketUtil.dnsQtype(v.payload)
        if (qtype != 1) {
            val reply = PacketUtil.buildUdpDnsNodata(v.dst, v.dport, v.src, v.sport, v.payload)
            if (reply.isNotEmpty()) {
                writeTun(reply)
                dnsOut.incrementAndGet()
            }
            return
        }
        val qname = PacketUtil.dnsQname(v.payload)
        if (qname.isEmpty()) {
            val reply = PacketUtil.buildUdpDnsServfail(v.dst, v.dport, v.src, v.sport, v.payload)
            if (reply.isNotEmpty()) writeTun(reply)
            return
        }

        dns.lookupIp(qname)?.let { cached ->
            emitDnsA(v, qname, cached, "cached")
            return
        }

        if (dnsInflight.get() >= config.maxDnsInflight) {
            // Desktop reinjects; VpnService cannot — SERVFAIL instead of blackhole.
            val reply = PacketUtil.buildUdpDnsServfail(v.dst, v.dport, v.src, v.sport, v.payload)
            if (reply.isNotEmpty()) writeTun(reply)
            log("DNS overloaded SERVFAIL $qname")
            return
        }

        val payload = v.payload.copyOf()
        val src = v.src
        val sport = v.sport
        val dst = v.dst
        val dport = v.dport
        dnsInflight.incrementAndGet()
        pool.execute {
            try {
                dns.lookupIp(qname)?.let { cached ->
                    val reply = PacketUtil.buildUdpDnsReply(dst, dport, src, sport, payload, cached)
                    if (reply.isNotEmpty()) {
                        writeTun(reply)
                        dnsOut.incrementAndGet()
                    }
                    return@execute
                }
                val real = resolver.resolveIpv4Fast(qname, dst)
                val answer = dns.bindName(qname, real)
                if (answer == 0) {
                    val reply = PacketUtil.buildUdpDnsServfail(dst, dport, src, sport, payload)
                    if (reply.isNotEmpty()) writeTun(reply)
                    log("DNS bind fail SERVFAIL $qname")
                    return@execute
                }
                val note = when {
                    DnsBinder.isStandinIp(answer) && real != null -> "stand-in/collision"
                    DnsBinder.isStandinIp(answer) -> "stand-in/no-resolve"
                    else -> "redir-host"
                }
                val reply = PacketUtil.buildUdpDnsReply(dst, dport, src, sport, payload, answer)
                if (reply.isEmpty()) return@execute
                writeTun(reply)
                dnsOut.incrementAndGet()
                val decision = rules.decide(qname)
                if (dnsLogLeft.getAndDecrement() > 0 || config.logDecisions) {
                    log(
                        "DNS ${decision.outbound.ifEmpty { "DIRECT" }} $qname -> " +
                            "${PacketUtil.ipToString(answer)} ($note/${decision.matched})"
                    )
                }
            } finally {
                dnsInflight.decrementAndGet()
            }
        }
    }

    private fun emitDnsA(v: PacketUtil.Ipv4L4, qname: String, ip: Int, note: String) {
        val reply = PacketUtil.buildUdpDnsReply(v.dst, v.dport, v.src, v.sport, v.payload, ip)
        if (reply.isEmpty()) return
        writeTun(reply)
        dnsOut.incrementAndGet()
        if (dnsLogLeft.getAndDecrement() > 0 || config.logDecisions) {
            val decision = rules.decide(qname)
            log(
                "DNS ${decision.outbound.ifEmpty { "DIRECT" }} $qname -> " +
                    "${PacketUtil.ipToString(ip)} ($note/${decision.matched})"
            )
        }
    }

    /**
     * DNS-over-TCP via default MultiLink to 8.8.8.8:53
     * (internet.cpp resolve_ipv4_via_socks).
     */
    private fun resolveViaProxyDnsTcp(qname: String): Int? {
        val link = config.findLink(config.defaultLink) ?: return null
        val query = resolver.buildQueryAPublic(qname)
        if (query.isEmpty()) return null
        val session = VortexSession(link) { sock ->
            protectAny(sock)
            true
        }
        return try {
            if (!session.connectTarget("8.8.8.8", 53)) return null
            // Vortex DATA carries raw DNS-over-TCP: [u16 len][message].
            val wire = ByteArray(2 + query.size)
            wire[0] = ((query.size ushr 8) and 0xff).toByte()
            wire[1] = (query.size and 0xff).toByte()
            System.arraycopy(query, 0, wire, 2, query.size)
            if (!session.sendData(wire)) return null
            val buf = ArrayList<Byte>(512)
            val deadline = System.currentTimeMillis() + 8000
            while (System.currentTimeMillis() < deadline) {
                val frame = session.recvFrame() ?: break
                when (frame.first) {
                    VortexCmd.DATA -> frame.second.forEach { buf += it }
                    VortexCmd.CLOSE, VortexCmd.CONNECT_FAIL -> break
                }
                if (buf.size >= 2) {
                    val rlen = ((buf[0].toInt() and 0xff) shl 8) or (buf[1].toInt() and 0xff)
                    if (rlen in 12..4096 && buf.size >= 2 + rlen) {
                        val dnsMsg = ByteArray(rlen) { i -> buf[2 + i] }
                        val (r, ip) = resolver.parseDnsA(dnsMsg, rlen)
                        return if (r == DnsResolver.Result.Ok) ip else null
                    }
                }
            }
            null
        } catch (_: Exception) {
            null
        } finally {
            try { session.close() } catch (_: Exception) {}
        }
    }

    private fun handleTcp(v: PacketUtil.Ipv4L4) {
        val key = FlowKey(v.src, v.dst, v.sport, v.dport)
        val syn = v.tcpFlags and PacketUtil.TCP_SYN != 0
        val ack = v.tcpFlags and PacketUtil.TCP_ACK != 0
        val learnedName = dns.lookupName(v.dst)
        val existing = flows[key]

        if (syn && !ack) {
            if (existing != null) return
            if (flows.size >= config.maxConnections) {
                log("max_connections ${config.maxConnections}")
                return
            }
            val learned = !learnedName.isNullOrEmpty()
            val host = learnedName ?: PacketUtil.ipToString(v.dst)
            // Force browsers back to system DNS (redir-host): blocking DoH/DoT
            // otherwise Chrome resolves real IPs then PASSTHRU fails under GFW.
            if (learned && isDohHost(host)) {
                val rst = PacketUtil.buildTcpPacket(
                    v.dst, v.dport, v.src, v.sport,
                    0, (v.seq + 1) and 0xffffffffL,
                    PacketUtil.TCP_RST or PacketUtil.TCP_ACK, ByteArray(0),
                    mss = config.mss
                )
                writeTun(rst)
                if (config.logConnections) log("block DoH $host:${v.dport}")
                return
            }
            val flow = TcpFlow(
                key = key,
                host = host,
                learned = learned,
                clientNext = (v.seq + 1) and 0xffffffffL,
                serverSeq = (System.nanoTime() and 0xffffffffL),
                serverAck = (v.seq + 1) and 0xffffffffL
            )
            flows[key] = flow
            val synAck = PacketUtil.buildTcpPacket(
                v.dst, v.dport, v.src, v.sport,
                flow.serverSeq, flow.serverAck,
                PacketUtil.TCP_SYN or PacketUtil.TCP_ACK, ByteArray(0),
                mss = config.mss
            )
            flow.serverSeq = (flow.serverSeq + 1) and 0xffffffffL
            writeTun(synAck)
            if (config.logConnections) {
                val tag = when {
                    learned -> "TCP SYN"
                    DnsBinder.isPrivateIpDivert(v.dst) -> "TCP PASSTHRU"
                    else -> "TCP IP-PROXY"
                }
                log("$tag $host:${flow.key.dport}")
            }
            pool.execute { openUpstream(flow) }
            return
        }

        val flow = existing ?: return
        if (!flow.alive) return
        flow.lastActiveMs = System.currentTimeMillis()

        if (v.tcpFlags and PacketUtil.TCP_RST != 0) {
            closeFlow(flow)
            flows.remove(key)
            return
        }

        if (v.payload.isNotEmpty()) {
            flow.clientNext = (v.seq + v.payload.size) and 0xffffffffL
            flow.serverAck = flow.clientNext
            val ok = forwardPayload(flow, v.payload)
            val ackPkt = PacketUtil.buildTcpPacket(
                v.dst, v.dport, v.src, v.sport,
                flow.serverSeq, flow.serverAck,
                PacketUtil.TCP_ACK, ByteArray(0),
                mss = config.mss
            )
            writeTun(ackPkt)
            if (!ok) {
                sendRst(flow)
                closeFlow(flow)
                flows.remove(key)
                return
            }
        }

        if (v.tcpFlags and PacketUtil.TCP_FIN != 0) {
            // Half-close upstream (desktop fin_from_client → shutdown SD_SEND).
            flow.serverAck = (flow.serverAck + 1) and 0xffffffffL
            halfCloseUpstream(flow)
            val finAck = PacketUtil.buildTcpPacket(
                v.dst, v.dport, v.src, v.sport,
                flow.serverSeq, flow.serverAck,
                PacketUtil.TCP_FIN or PacketUtil.TCP_ACK, ByteArray(0),
                mss = config.mss
            )
            flow.serverSeq = (flow.serverSeq + 1) and 0xffffffffL
            writeTun(finAck)
            closeFlow(flow)
            flows.remove(key)
        }
    }

    private fun halfCloseUpstream(flow: TcpFlow) {
        try {
            flow.session?.sendClose()
        } catch (_: Exception) {
        }
        try {
            flow.direct?.shutdownOutput()
        } catch (_: Exception) {
        }
    }

    private fun isDohHost(host: String): Boolean {
        val h = host.lowercase()
        if (h == "dns.google" || h == "dns.google.com") return true
        if (h == "cloudflare-dns.com" || h.endsWith(".cloudflare-dns.com")) return true
        if (h.endsWith(".dns.quad9.net") || h == "dns.quad9.net") return true
        if (h.contains("dns.nextdns.io") || h.endsWith(".opendns.com")) return true
        if (h.startsWith("doh.") || h.contains("dns-tls") || h.contains("dns.adguard")) return true
        return false
    }

    private fun openUpstream(flow: TcpFlow) {
        try {
            if (!flow.learned) {
                // Private → protect direct (LAN). Public IP (DoH residual / Alt-Svc)
                // → default MultiLink CONNECT(ATYP_IPV4), not GFW-facing passthrough.
                if (DnsBinder.isPrivateIpDivert(flow.key.dst)) {
                    openDirectIp(flow, flow.key.dst)
                } else {
                    openProxyIp(flow, flow.key.dst)
                }
                return
            }
            // Match divert→SOCKS CONNECT(domain): decide on domain only (has_ip=false)
            // so GEOIP,CN,no-resolve cannot steal poisoned CDN IPs.
            val decision = rules.decide(flow.host)
            if (config.logDecisions || config.logConnections) {
                log("TCP ${decision.outbound.ifEmpty { "DIRECT" }} ${flow.host}:${flow.key.dport} (${decision.matched})")
            }
            if (decision.action == Action.Direct) {
                val destIp = if (!DnsBinder.isStandinIp(flow.key.dst)) {
                    flow.key.dst
                } else {
                    resolver.resolveIpv4Fast(flow.host, 0x08080808)
                        ?: throw IllegalStateException("DIRECT resolve fail ${flow.host}")
                }
                openDirectIp(flow, destIp)
            } else {
                val link = config.findLink(decision.outbound)
                    ?: config.findLink(config.defaultLink)
                    ?: run {
                        log("no link for ${decision.outbound}")
                        sendRst(flow)
                        closeFlow(flow)
                        flows.remove(flow.key)
                        return
                    }
                val session = VortexSession(link) { sock ->
                    protectAny(sock)
                    true
                }
                if (!session.connectTarget(flow.host, flow.key.dport)) {
                    log("CONNECT fail ${flow.host} via ${link.name}")
                    session.close()
                    sendRst(flow)
                    closeFlow(flow)
                    flows.remove(flow.key)
                    return
                }
                if (config.logConnections) log("CONNECT ok ${flow.host} via ${link.name}")
                flow.session = session
                markUpstreamReady(flow)
                pool.execute { pumpVortex(flow) }
            }
        } catch (e: Exception) {
            log("upstream ${flow.host}: ${e.javaClass.simpleName}: ${e.message}")
            sendRst(flow)
            closeFlow(flow)
            flows.remove(flow.key)
        }
    }

    private fun openDirectIp(flow: TcpFlow, destIp: Int) {
        val s = Socket()
        protectAny(s)
        s.tcpNoDelay = true
        s.soTimeout = config.divertIdleTimeoutSec * 1000
        s.connect(
            InetSocketAddress(InetAddress.getByAddress(intToIpv4Bytes(destIp)), flow.key.dport),
            15_000
        )
        flow.direct = s
        markUpstreamReady(flow)
        pool.execute { pumpDirect(flow) }
    }

    private fun openProxyIp(flow: TcpFlow, destIp: Int) {
        val link = config.findLink(config.defaultLink)
            ?: throw IllegalStateException("no default link")
        val session = VortexSession(link) { sock ->
            protectAny(sock)
            true
        }
        if (!session.connectIpv4(destIp, flow.key.dport)) {
            session.close()
            throw IllegalStateException("CONNECT IP fail ${PacketUtil.ipToString(destIp)}")
        }
        if (config.logConnections) {
            log("CONNECT ok IP ${PacketUtil.ipToString(destIp)} via ${link.name}")
        }
        flow.session = session
        markUpstreamReady(flow)
        pool.execute { pumpVortex(flow) }
    }

    private fun markUpstreamReady(flow: TcpFlow) {
        synchronized(flow.pendingLock) {
            flow.upstreamReady = true
            for (p in flow.pending) {
                if (!writeUpstream(flow, p)) {
                    flow.alive = false
                    break
                }
            }
            flow.pending.clear()
        }
    }

    private fun forwardPayload(flow: TcpFlow, payload: ByteArray): Boolean {
        synchronized(flow.pendingLock) {
            if (!flow.upstreamReady) {
                flow.pending.add(payload.copyOf())
                return true
            }
        }
        return writeUpstream(flow, payload)
    }

    private fun writeUpstream(flow: TcpFlow, payload: ByteArray): Boolean {
        return try {
            flow.session?.let { return it.sendData(payload) }
            flow.direct?.let {
                it.getOutputStream().write(payload)
                it.getOutputStream().flush()
                return true
            }
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun pumpVortex(flow: TcpFlow) {
        val session = flow.session ?: return
        while (running.get() && flow.alive) {
            val frame = session.recvFrame() ?: break
            when (frame.first) {
                VortexCmd.DATA -> {
                    if (frame.second.isNotEmpty()) {
                        flow.lastActiveMs = System.currentTimeMillis()
                        injectData(flow, frame.second)
                    }
                }
                VortexCmd.CLOSE, VortexCmd.CONNECT_FAIL -> break
            }
        }
        // Desktop: upstream EOF → FIN|ACK (not RST).
        if (flow.alive) sendFin(flow)
        closeFlow(flow)
        flows.remove(flow.key)
    }

    private fun pumpDirect(flow: TcpFlow) {
        val s = flow.direct ?: return
        val buf = ByteArray(16 * 1024)
        try {
            val input = s.getInputStream()
            while (running.get() && flow.alive) {
                val n = try {
                    input.read(buf)
                } catch (_: java.net.SocketTimeoutException) {
                    if (!flow.alive) break
                    continue
                }
                if (n < 0) break
                if (n == 0) continue
                flow.lastActiveMs = System.currentTimeMillis()
                injectData(flow, buf.copyOf(n))
            }
        } catch (_: Exception) {
        }
        if (flow.alive) sendFin(flow)
        closeFlow(flow)
        flows.remove(flow.key)
    }

    private fun injectData(flow: TcpFlow, data: ByteArray) {
        var off = 0
        val chunkMax = minOf(1200, config.mss)
        while (off < data.size && flow.alive) {
            val n = minOf(chunkMax, data.size - off)
            val chunk = data.copyOfRange(off, off + n)
            val pkt = PacketUtil.buildTcpPacket(
                flow.key.dst, flow.key.dport, flow.key.src, flow.key.sport,
                flow.serverSeq, flow.serverAck,
                PacketUtil.TCP_ACK or PacketUtil.TCP_PSH, chunk,
                mss = config.mss
            )
            flow.serverSeq = (flow.serverSeq + n) and 0xffffffffL
            writeTun(pkt)
            off += n
        }
    }

    private fun sendFin(flow: TcpFlow) {
        val pkt = PacketUtil.buildTcpPacket(
            flow.key.dst, flow.key.dport, flow.key.src, flow.key.sport,
            flow.serverSeq, flow.serverAck,
            PacketUtil.TCP_FIN or PacketUtil.TCP_ACK, ByteArray(0),
            mss = config.mss
        )
        flow.serverSeq = (flow.serverSeq + 1) and 0xffffffffL
        writeTun(pkt)
    }

    private fun sendRst(flow: TcpFlow) {
        val pkt = PacketUtil.buildTcpPacket(
            flow.key.dst, flow.key.dport, flow.key.src, flow.key.sport,
            flow.serverSeq, flow.serverAck, PacketUtil.TCP_RST, ByteArray(0),
            mss = config.mss
        )
        writeTun(pkt)
    }

    private fun closeFlow(flow: TcpFlow) {
        flow.alive = false
        try { flow.session?.close() } catch (_: Exception) {}
        try { flow.direct?.close() } catch (_: Exception) {}
        flow.session = null
        flow.direct = null
        synchronized(flow.pendingLock) { flow.pending.clear() }
    }

    private fun intToIpv4Bytes(hostOrder: Int): ByteArray = byteArrayOf(
        ((hostOrder ushr 24) and 0xff).toByte(),
        ((hostOrder ushr 16) and 0xff).toByte(),
        ((hostOrder ushr 8) and 0xff).toByte(),
        (hostOrder and 0xff).toByte()
    )

    companion object {
        private const val TAG = "TunEngine"
    }
}
