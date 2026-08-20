# Copyright (C) 2026 Taylor Kimball
# SPDX-License-Identifier: GPL-3.0-only

set -eu

config=/tmp/ircd.yaml

/ircd-bin/ergo defaultconfig > "$config"
sed -i \
  -e 's|"127.0.0.1:6667":|":6667":|' \
  -e 's|"\[::1\]:6667":|# "[::1]:6667":|' \
  -e 's|motd: ergo.motd|motd: /ircd/ergo.motd|' \
  -e 's|path: languages|path: /ircd-bin/languages|' \
  "$config"

cd /tmp
/ircd-bin/ergo mkcerts --conf "$config"
exec /ircd-bin/ergo run --conf "$config"
