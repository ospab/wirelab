# OSTP server: the release binary, a config written from the recipe's
# parameters, started in the background. Log: /lab/ostp.log.
set -eu
. /lab/recipe.env
mkdir -p /opt/ostp
tar -xzf /lab/dl/ostp.pkg -C /opt/ostp 2>/dev/null || cp /lab/dl/ostp.pkg /opt/ostp/ostp
chmod +x /opt/ostp/ostp
/opt/ostp/ostp -V

tls=false
[ "$WL_P_TRANSPORT" = tls ] && tls=true
# local_access: the lab's target is on a private network, which the server
# otherwise refuses to relay to.
# TLS: OSTP accepts it on its own port too. The nginx frontend keeps it off
# ports 80 and 443; with no certificate yet it serves a self-signed one.
cat > /opt/ostp/config.json <<CONF
{
  "mode": "server",
  "config_version": 3,
  "log_level": "$WL_P_LOG_LEVEL",
  "listen": "0.0.0.0:$WL_SERVER_PORT",
  "access_keys": ["$WL_P_KEY"],
  "local_access": true,
  "domain": "server.lab",
  "tls": {
    "enabled": $tls,
    "frontend": "nginx",
    "ws_path": "/wl-$WL_P_KEY",
    "cert": "acme",
    "public_port": $WL_SERVER_PORT,
    "acme": { "email": "", "staging": true }
  },
  "debug": false
}
CONF
cd /opt/ostp
nohup ./ostp -c /opt/ostp/config.json > /lab/ostp.log 2>&1 &
echo "ostp server started, pid $!, transport $WL_P_TRANSPORT, port $WL_SERVER_PORT"
