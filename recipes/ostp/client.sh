# OSTP client: SOCKS5/HTTP proxy on 127.0.0.1:1088 to the lab server.
# Log: /lab/ostp.log.
set -eu
. /lab/recipe.env
mkdir -p /opt/ostp
tar -xzf /lab/dl/ostp.pkg -C /opt/ostp 2>/dev/null || cp /lab/dl/ostp.pkg /opt/ostp/ostp
chmod +x /opt/ostp/ostp
/opt/ostp/ostp -V

case "$WL_P_TRANSPORT" in
    udp)
        onoff() { [ "$1" = on ] && echo true || echo false; }
        transport="{ \"mode\": \"udp\", \"ttl_desync\": $(onoff "$WL_P_TTL_DESYNC"), \"ttl_desync_auto\": $(onoff "$WL_P_TTL_DESYNC_AUTO"), \"ttl_desync_ttl\": $WL_P_TTL_DESYNC_TTL, \"ttl_desync_count\": $WL_P_TTL_DESYNC_COUNT }" ;;
    uot) transport='{ "mode": "uot" }' ;;
    tls) transport='{ "mode": "uot", "tls": true, "tls_sni": "server.lab", "tls_insecure": true }' ;;
    *) echo "transport $WL_P_TRANSPORT: expected udp, uot or tls"; exit 1 ;;
esac
cat > /opt/ostp/config.json <<CONF
{
  "mode": "client",
  "config_version": 4,
  "log_level": "$WL_P_LOG_LEVEL",
  "server": "$WL_SERVER_ADDR:$WL_SERVER_PORT",
  "access_key": "$WL_P_KEY",
  "socks5_bind": "127.0.0.1:1088",
  "exclude": { "domains": [], "ips": [], "processes": [] },
  "transport": $transport,
  "debug": false
}
CONF
cd /opt/ostp
nohup ./ostp -c /opt/ostp/config.json > /lab/ostp.log 2>&1 &
echo "ostp client started, pid $!, transport $WL_P_TRANSPORT"
