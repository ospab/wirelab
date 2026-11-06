# Xray REALITY client: SOCKS5 on 127.0.0.1:1080. Waits for the server's
# public key in /shared. Log: /lab/xray.log.
set -eu
. /lab/recipe.env
mkdir -p /opt/xray && cd /opt/xray
unzip -oq /lab/dl/xray.zip xray
chmod +x xray
i=0
while [ ! -s /shared/reality.pub ]; do
    i=$((i + 1)); [ $i -gt 600 ] && { echo "no /shared/reality.pub from the server after 60 s"; exit 1; }
    sleep 0.1
done
pub=$(cat /shared/reality.pub)
uuid=$(echo "$WL_P_ID" | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/')
cat > /opt/xray/client.json <<CONF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{ "listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": { "udp": true } }],
  "outbounds": [{
    "protocol": "vless",
    "settings": { "vnext": [{ "address": "$WL_SERVER_ADDR", "port": $WL_SERVER_PORT,
                              "users": [{ "id": "$uuid", "flow": "$WL_P_FLOW", "encryption": "none" }] }] },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": { "serverName": "$WL_P_SNI", "fingerprint": "$WL_P_FINGERPRINT",
                           "publicKey": "$pub", "shortId": "$WL_P_SHORT_ID" }
    }
  }]
}
CONF
nohup ./xray run -c /opt/xray/client.json > /lab/xray.log 2>&1 &
echo "xray client started, pid $!"
