set -eu

compose_file=tests/integration/compose.yml
project=${BOTNATS_COMPOSE_PROJECT:-botnats-test}

compose() {
  docker compose --file "$compose_file" --project-name "$project" "$@"
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ]; then
    compose logs --no-color || true
  fi
  compose down --volumes --remove-orphans || true
  exit "$status"
}

wait_ready() {
  service=$1
  attempts=0
  stable=0
  while [ "$stable" -lt 3 ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 60 ]; then
      echo "$service did not become ready" >&2
      return 1
    fi
    if compose exec -T "$service" \
      wget -qO- http://127.0.0.1:8080/ready 2>/dev/null | grep -qx ok; then
      stable=$((stable + 1))
    else
      stable=0
    fi
    if [ "$stable" -lt 3 ]; then
      sleep 1
    fi
  done
}

trap cleanup EXIT INT TERM
compose down --volumes --remove-orphans
compose build alpha
compose up --detach --no-build --wait --wait-timeout 120

nats_address=$(compose port nats-1 4222)
export BOTNATS_TEST_IRC_ADDRESS="$(compose port irc 6667)"
export BOTNATS_TEST_JETSTREAM_REPLICAS=3
export BOTNATS_TEST_NATS_TOKEN=integration-token
export BOTNATS_TEST_NATS_URL="nats://$nats_address"
export BOTNATS_TEST_NATS_URLS="nats://$(compose port nats-1 4222),nats://$(compose port nats-2 4222),nats://$(compose port nats-3 4222)"

venv/bin/python -m unittest tests.test_coordinator_integration.CoordinatorIntegrationTests -v

leader=$(venv/bin/python tests/integration/test_failover.py leader)
case "$leader" in
  nats-1|nats-2|nats-3) ;;
  *)
    echo "unexpected JetStream leader: $leader" >&2
    exit 1
    ;;
esac
compose kill "$leader"
for service in alpha beta gamma; do
  wait_ready "$service"
done
venv/bin/python tests/integration/test_failover.py claim "$leader"
compose up --detach --no-build --wait --wait-timeout 120 "$leader"
nats_address=$(compose port nats-1 4222)
export BOTNATS_TEST_NATS_URL="nats://$nats_address"

venv/bin/python tests/integration/test_restart.py mark
compose kill nats-1 nats-2 nats-3
compose up --detach --no-build --wait --wait-timeout 120
for service in alpha beta gamma; do
  wait_ready "$service"
done
nats_address=$(compose port nats-1 4222)
export BOTNATS_TEST_NATS_URL="nats://$nats_address"
venv/bin/python tests/integration/test_restart.py check

BOTNATS_TEST_TOTP_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ \
  venv/bin/python tests/integration/test_mesh.py

for service in alpha beta gamma; do
  compose restart "$service"
  wait_ready "$service"
  BOTNATS_TEST_RESTARTED_BOT="$service" \
    venv/bin/python -m tests.integration.test_bot_restart
done
