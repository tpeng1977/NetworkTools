package com.vortex.internet.tun

/**
 * Sticky IP↔name map matching internet.cpp dns_bind_name:
 * prefer unique real A; stand-in 198.18 only on collision / resolve miss.
 */
class DnsBinder {
    private val lock = Any()
    private val ipToName = HashMap<Int, String>()
    private val nameToIp = HashMap<String, Int>()
    private val standIn = PacketUtil.AtomicCounter()

    fun lookupName(ipHostOrder: Int): String? = synchronized(lock) { ipToName[ipHostOrder] }

    fun lookupIp(qname: String): Int? = synchronized(lock) { nameToIp[qname.lowercase()] }

    fun bindName(qnameRaw: String, realIp: Int?): Int {
        val qname = qnameRaw.lowercase()
        if (qname.isEmpty() || qname == "?") return 0
        synchronized(lock) {
            nameToIp[qname]?.let { return it }

            if (realIp != null && realIp != 0 &&
                !isPrivateIpDivert(realIp) && !isStandinIp(realIp)
            ) {
                val owner = ipToName[realIp]
                if (owner == null) {
                    ipToName[realIp] = qname
                    nameToIp[qname] = realIp
                    return realIp
                }
                if (owner == qname) {
                    nameToIp[qname] = realIp
                    return realIp
                }
                // Shared/poisoned IP already owned by another name → unique stand-in.
            }
            return allocStandinLocked(qname)
        }
    }

    private fun allocStandinLocked(qname: String): Int {
        repeat(65536) {
            val stand = PacketUtil.nextStandIn(standIn)
            if (ipToName.containsKey(stand)) return@repeat
            ipToName[stand] = qname
            nameToIp[qname] = stand
            return stand
        }
        return 0
    }

    companion object {
        fun isStandinIp(ipHostOrder: Int): Boolean =
            (ipHostOrder and 0xFFFE0000.toInt()) == 0xC6120000.toInt()

        /**
         * Narrow private set matching internet.cpp WinDivert is_private_ip
         * (not the wider rules.hpp GEOIP,private set).
         */
        fun isPrivateIpDivert(ipHostOrder: Int): Boolean {
            val b0 = (ipHostOrder ushr 24) and 0xff
            val b1 = (ipHostOrder ushr 16) and 0xff
            if (b0 == 10) return true
            if (b0 == 127) return true
            if (b0 == 192 && b1 == 168) return true
            if (b0 == 169 && b1 == 254) return true
            if (b0 == 172 && b1 in 16..31) return true
            return false
        }
    }
}
