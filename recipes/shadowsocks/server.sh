# shadowsocks-rust server on the lab port, TCP and UDP. Log: /lab/ss.log.
set -eu
. /lab/recipe.env
mkdir -p /opt/ss && cd /opt/ss
xzcat /lab/dl/ss.tar.xz | tar -x
case "$WL_P_METHOD" in
    # The 2022 methods take the raw key in base64.
    2022-*) pass=$(printf '%s' "$WL_P_KEY" | sed 's/../\\x&/g' | { read -r esc; printf "$esc"; } | base64) ;;
    *) pass=$WL_P_KEY ;;
esac
./ssserver --version
nohup ./ssserver -U -s "0.0.0.0:$WL_SERVER_PORT" -m "$WL_P_METHOD" -k "$pass" > /lab/ss.log 2>&1 &
echo "ssserver started, pid $!, $WL_P_METHOD on $WL_SERVER_PORT"
