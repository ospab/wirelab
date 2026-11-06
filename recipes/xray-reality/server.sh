# Xray REALITY server. The x25519 key pair is made here; the client reads
# the public key from /shared. REALITY borrows handshakes from a TLS 1.3 site:
# a local nginx with a self-signed certificate, so nothing leaves the lab.
# openssl comes from Alpine packages (the container needs the internet once).
set -eu
. /lab/recipe.env
command -v openssl > /dev/null || apk add --no-cache openssl > /dev/null
mkdir -p /opt/xray && cd /opt/xray
unzip -oq /lab/dl/xray.zip xray
chmod +x xray
./xray version | head -1

uuid=$(echo "$WL_P_ID" | sed -E 's/(.{8})(.{4})(.{4})(.{4})(.{12})/\1-\2-\3-\4-\5/')
keys=$(./xray x25519)
priv=$(echo "$keys" | awk -F': *' '/^Private ?[Kk]ey/ { print $2 }')
# Newer releases call the public key "Password".
pub=$(echo "$keys" | awk -F': *' '/^(Public ?[Kk]ey|Password)/ { print $2 }' | head -1)
[ -n "$priv" ] && [ -n "$pub" ] || { echo "could not read the key pair from: $keys"; exit 1; }

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=$WL_P_SNI" -addext "subjectAltName=DNS:$WL_P_SNI" \
    -keyout /opt/xray/site.key -out /opt/xray/site.crt 2> /dev/null
cat > /opt/xray/site.conf <<CONF
worker_processes 1;
error_log /lab/site-nginx.log warn;
pid /tmp/site-nginx.pid;
events {}
http {
    access_log off;
    server {
        listen 127.0.0.1:8443 ssl;
        http2 on;
        ssl_protocols TLSv1.3;
        ssl_certificate /opt/xray/site.crt;
        ssl_certificate_key /opt/xray/site.key;
        location / { return 200 "lab site\n"; }
    }
}
CONF
nginx -c /opt/xray/site.conf

cat > /opt/xray/server.json <<CONF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0", "port": $WL_SERVER_PORT, "protocol": "vless",
    "settings": { "clients": [{ "id": "$uuid", "flow": "$WL_P_FLOW" }], "decryption": "none" },
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": { "dest": "127.0.0.1:8443", "serverNames": ["$WL_P_SNI"],
                           "privateKey": "$priv", "shortIds": ["$WL_P_SHORT_ID"] }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
CONF
nohup ./xray run -c /opt/xray/server.json > /lab/xray.log 2>&1 &
echo "$pub" > /shared/reality.pub.tmp && mv /shared/reality.pub.tmp /shared/reality.pub
echo "xray server started, pid $!, port $WL_SERVER_PORT"
