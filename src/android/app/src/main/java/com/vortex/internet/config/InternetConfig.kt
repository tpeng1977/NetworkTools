package com.vortex.internet.config

import android.content.Context
import com.vortex.internet.rules.Cidr
import com.vortex.internet.rules.RulesEngine
import com.vortex.internet.vortex.LinkEndpoint
import org.json.JSONObject

data class InternetConfig(
    val links: Map<String, LinkEndpoint>,
    val defaultLink: String,
    val rulesYaml: String,
    val geoipCn: List<Cidr>,
    val geositeCn: Set<String>,
    val logDecisions: Boolean,
    val logConnections: Boolean,
    val divertIdleTimeoutSec: Int,
    val mss: Int,
    val maxConnections: Int,
    val maxDnsInflight: Int
) {
    fun findLink(name: String): LinkEndpoint? {
        links[name]?.let { return it }
        if (name.isEmpty() || name == "proxy") return links[defaultLink]
        return null
    }

    companion object {
        fun loadFromAssets(context: Context, configAsset: String = "internet.json"): InternetConfig {
            val jsonText = context.assets.open(configAsset).bufferedReader().use { it.readText() }
            val root = JSONObject(jsonText)
            val multi = root.getJSONObject("multilink")
            val links = linkedMapOf<String, LinkEndpoint>()
            // Prefer declaration order: link1, link2, link3 (desktop first-key default).
            val names = mutableListOf<String>()
            val keys = multi.keys()
            while (keys.hasNext()) names += keys.next()
            names.sort()
            for (name in names) {
                val o = multi.getJSONObject(name)
                links[name] = LinkEndpoint(
                    name = name,
                    serverIp = o.getString("server_ip"),
                    serverPort = o.getInt("server_port"),
                    masterSecret = o.getString("master_secret"),
                    peerSecret = o.optString("peer_secret", ""),
                    paddingMin = o.optInt("padding_min", 8),
                    paddingMax = o.optInt("padding_max", 64),
                    idleTimeoutSec = o.optInt("idle_timeout_sec", 300),
                    maxPayload = o.optInt("max_payload", 32768)
                )
            }
            require(links.isNotEmpty()) { "multilink empty in $configAsset" }
            val defaultLink = when {
                links.containsKey("link1") -> "link1"
                else -> links.keys.first()
            }
            val rulesPath = root.optString("rules_path", "rules.yaml")
            val rulesAsset = when {
                rulesPath.endsWith("multirules.yaml") || rulesPath.endsWith("rules.yaml") ->
                    rulesPath.substringAfterLast('/').substringAfterLast('\\').let {
                        if (it == "multirules.yaml") "rules.yaml" else it
                    }
                else -> "rules.yaml"
            }
            val rulesYaml = try {
                context.assets.open(rulesAsset).bufferedReader().use { it.readText() }
            } catch (_: Exception) {
                context.assets.open("rules.yaml").bufferedReader().use { it.readText() }
            }

            val geoipAsset = assetNameFromJsonPath(
                root.optString("geoip_cn", "config/geo/geoip-cn.txt"),
                "geo/geoip-cn.txt"
            )
            val geositeAsset = assetNameFromJsonPath(
                root.optString("geosite_cn", "config/geo/geosite-cn.txt"),
                "geo/geosite-cn.txt"
            )
            val geoipCn = openAssetReader(context, geoipAsset)?.useLines { RulesEngine.loadCidrList(it) }
                ?: emptyList()
            val geositeCn = openAssetReader(context, geositeAsset)?.useLines { RulesEngine.loadDomainList(it) }
                ?: emptySet()

            // Overlay divert keys (InternetConfig in config.hpp).
            var divertIdle = root.optInt("divert_idle_timeout_sec", 180).coerceAtLeast(1)
            var mss = root.optInt("mss", 1200).coerceAtLeast(200)
            var maxConn = root.optInt("max_connections", 2048).coerceAtLeast(1)
            var maxDns = root.optInt("max_dns_inflight", 64).coerceAtLeast(1)

            return InternetConfig(
                links = links,
                defaultLink = defaultLink,
                rulesYaml = rulesYaml,
                geoipCn = geoipCn,
                geositeCn = geositeCn,
                logDecisions = root.optBoolean("log_decisions", false),
                logConnections = root.optBoolean("log_connections", true),
                divertIdleTimeoutSec = divertIdle,
                mss = mss,
                maxConnections = maxConn,
                maxDnsInflight = maxDns
            )
        }

        private fun assetNameFromJsonPath(jsonPath: String, fallback: String): String {
            if (jsonPath.isBlank()) return fallback
            val name = jsonPath.replace('\\', '/').substringAfterLast('/')
            return if (name.isNotEmpty()) "geo/$name" else fallback
        }

        private fun openAssetReader(context: Context, asset: String): java.io.BufferedReader? {
            return try {
                context.assets.open(asset).bufferedReader()
            } catch (_: Exception) {
                try {
                    context.assets.open("geo/${asset.substringAfterLast('/')}").bufferedReader()
                } catch (_: Exception) {
                    null
                }
            }
        }
    }
}
