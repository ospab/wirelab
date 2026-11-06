# shadowsocks-rust local: SOCKS5 on 127.0.0.1:1080. Log: /lab/ss.log.
set -eu
. /lab/recipe.env
mkdir -p /opt/ss && cd /opt/ss
xzcat /lab/dl/ss.tar.xz | tar -x
case "$WL_P_METHOD" in
    2022-*) pass=$(printf '%s' "$WL_P_KEY" | sed 's/../\\x&/g' | { read -r esc; printf "$esc"; } | base64) ;;
    *) pass=$WL_P_KEY ;;
esac
nohup ./sslocal -U -b 127.0.0.1:1080 -s "$WL_SERVER_ADDR:$WL_SERVER_PORT" -m "$WL_P_METHOD" -k "$pass" > /lab/ss.log 2>&1 &
echo "sslocal started, pid $!"
