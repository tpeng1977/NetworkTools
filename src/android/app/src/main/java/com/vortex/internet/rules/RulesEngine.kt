package com.vortex.internet.rules

import java.net.InetAddress
import java.util.Locale

enum class Action { Direct, Proxy }

data class Decision(
    val action: Action,
    val outbound: String,
    val matched: String
)

data class Cidr(val network: Int, val mask: Int)

/**
 * Clash-style subset used by multilink/internet: DOMAIN, DOMAIN-SUFFIX,
 * DOMAIN-KEYWORD, IP-CIDR, GEOIP, GEOSITE, MATCH — same semantics as include/rules.hpp.
 */
class RulesEngine(
    yaml: String,
    private val cnCidrs: List<Cidr> = emptyList(),
    private val cnDomains: Set<String> = emptySet()
) {
    private data class Rule(
        val type: String,
        val value: String,
        val action: Action,
        val outbound: String,
        val noResolve: Boolean,
        val cidr: Cidr? = null
    )

    private val rules: List<Rule>
    val cnCidrCount: Int get() = cnCidrs.size
    val cnDomainCount: Int get() = cnDomains.size

    init {
        val list = mutableListOf<Rule>()
        for (raw in yaml.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line == "rules:") continue
            val item = line.removePrefix("-").trim()
            if (item.isEmpty()) continue
            val parts = item.split(',').map { it.trim() }
            if (parts.isEmpty()) continue
            val type = parts[0].uppercase(Locale.US)
            when (type) {
                "MATCH" -> {
                    val (act, out) = parseOutbound(parts.getOrNull(1) ?: "proxy")
                    list += Rule(type, "", act, out, true)
                }
                "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "GEOIP", "GEOSITE" -> {
                    if (parts.size < 3) continue
                    val (act, out) = parseOutbound(parts[2])
                    val noResolve = parts.drop(3).any { it.equals("no-resolve", true) }
                    list += Rule(type, parts[1].lowercase(Locale.US), act, out, noResolve)
                }
                "IP-CIDR" -> {
                    if (parts.size < 3) continue
                    val (act, out) = parseOutbound(parts[2])
                    val noResolve = parts.drop(3).any { it.equals("no-resolve", true) }
                    val c = parseCidr(parts[1]) ?: continue
                    list += Rule(type, parts[1], act, out, noResolve, c)
                }
            }
        }
        rules = list
    }

    fun decide(host: String, ipv4HostOrder: Int? = null): Decision {
        val h = host.lowercase(Locale.US)
        var ipKnown = ipv4HostOrder != null
        var ip = ipv4HostOrder ?: 0
        val hostIsIp = isDottedIpv4(h)
        if (!ipKnown && hostIsIp) {
            ipKnown = true
            ip = ipv4FromDotted(h) ?: 0
        }
        val isDomain = h.isNotEmpty() && !hostIsIp

        for (r in rules) {
            when (r.type) {
                "DOMAIN" -> if (isDomain && h == r.value)
                    return Decision(r.action, r.outbound, "DOMAIN,${r.value}")
                "DOMAIN-SUFFIX" -> if (isDomain && (h == r.value || h.endsWith("." + r.value)))
                    return Decision(r.action, r.outbound, "DOMAIN-SUFFIX,${r.value}")
                "DOMAIN-KEYWORD" -> if (isDomain && h.contains(r.value))
                    return Decision(r.action, r.outbound, "DOMAIN-KEYWORD,${r.value}")
                "GEOSITE" -> if (isDomain && r.value == "cn" && geositeCnMatch(h))
                    return Decision(r.action, r.outbound, "GEOSITE,cn")
                "IP-CIDR" -> {
                    // no-resolve: only when IP already known (desktop ensure_ip)
                    if (!ipKnown) continue
                    val c = r.cidr ?: continue
                    if (cidrContains(c, ip)) return Decision(r.action, r.outbound, "IP-CIDR")
                }
                "GEOIP" -> {
                    if (!ipKnown) continue // GEOIP,*,no-resolve — skip without real IP
                    when (r.value) {
                        "private" -> if (isPrivateIp(ip))
                            return Decision(r.action, r.outbound, "GEOIP,private")
                        "cn" -> if (geoipCnMatch(ip))
                            return Decision(r.action, r.outbound, "GEOIP,CN")
                    }
                }
                "MATCH" -> return Decision(r.action, r.outbound, "MATCH")
            }
        }
        return Decision(Action.Proxy, "proxy", "MATCH(default)")
    }

    private fun geositeCnMatch(host: String): Boolean {
        if (cnDomains.isEmpty()) return false
        var cur = host
        while (true) {
            if (cnDomains.contains(cur)) return true
            val dot = cur.indexOf('.')
            if (dot < 0) break
            cur = cur.substring(dot + 1)
        }
        return false
    }

    private fun geoipCnMatch(ip: Int): Boolean {
        for (c in cnCidrs) {
            if (cidrContains(c, ip)) return true
        }
        return false
    }

    private fun parseOutbound(s: String): Pair<Action, String> {
        val u = s.trim()
        if (u.equals("DIRECT", true)) return Action.Direct to ""
        return Action.Proxy to if (u.isEmpty()) "proxy" else u
    }

    companion object {
        fun parseCidr(cidr: String): Cidr? {
            val parts = cidr.trim().split('/')
            if (parts.size != 2) return null
            val prefix = parts[1].toIntOrNull() ?: return null
            if (prefix < 0 || prefix > 32) return null
            val addr = try {
                InetAddress.getByName(parts[0]).address
            } catch (_: Exception) {
                return null
            }
            if (addr.size != 4) return null
            var net = 0
            for (b in addr) net = (net shl 8) or (b.toInt() and 0xff)
            val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
            return Cidr(net and mask, mask)
        }

        fun cidrContains(c: Cidr, ipHostOrder: Int): Boolean =
            (ipHostOrder and c.mask) == c.network

        fun isPrivateIp(ip: Int): Boolean {
            val b0 = (ip ushr 24) and 0xff
            val b1 = (ip ushr 16) and 0xff
            if (b0 == 10) return true
            if (b0 == 127) return true
            if (b0 == 192 && b1 == 168) return true
            if (b0 == 169 && b1 == 254) return true
            if (b0 == 172 && b1 in 16..31) return true
            if (b0 == 100 && b1 in 64..127) return true // CGNAT
            if (b0 == 0) return true
            return false
        }

        fun isDottedIpv4(s: String): Boolean {
            val p = s.split('.')
            if (p.size != 4) return false
            return p.all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
        }

        fun ipv4FromDotted(s: String): Int? {
            val p = s.split('.')
            if (p.size != 4) return null
            var v = 0
            for (part in p) {
                val n = part.toIntOrNull() ?: return null
                if (n !in 0..255) return null
                v = (v shl 8) or n
            }
            return v
        }

        /** Load geoip-cn.txt style CIDR list (one CIDR per line). */
        fun loadCidrList(lines: Sequence<String>): List<Cidr> {
            val out = ArrayList<Cidr>(8192)
            for (raw in lines) {
                val line = raw.trim()
                if (line.isEmpty() || line[0] == '#' || line[0] == ';') continue
                parseCidr(line)?.let { out += it }
            }
            return out
        }

        /** Load geosite-cn.txt style domain list (Loyalsoldier full:/domain: prefixes OK). */
        fun loadDomainList(lines: Sequence<String>): Set<String> {
            val out = HashSet<String>(131072)
            for (raw in lines) {
                var line = raw.trim()
                if (line.isEmpty() || line[0] == '#' || line[0] == ';') continue
                if (line.startsWith("regexp:")) continue
                when {
                    line.startsWith("full:") -> line = line.substring(5)
                    line.startsWith("domain:") -> line = line.substring(7)
                }
                line = line.trim().lowercase(Locale.US)
                if (line.isNotEmpty()) out.add(line)
            }
            return out
        }
    }
}
