#! /bin/bash

# source .env file if present
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

: "${DS_PROXY_ADDRESS:=127.0.0.1:4444}"

PASSWORD='a good password'
KEYRING_FILE=/tmp/keyring.toml

DS_PROXY_LOG=/tmp/ds_proxy_log
NODE_LOG=/tmp/node_log
REDIS_PORT=5555

echo 'compiling ds_proxy'
cargo build --release

echo 'building simple node server which mimics a backend storage'
npm clean-install --ignore-scripts --prefix tests/fixtures/server-static

echo 'building keyring file'
./target/release/ds_proxy add-key --password-file <(echo -n "$PASSWORD") --keyring-file "$KEYRING_FILE"

if [ "$1" = "s3" ]; then
  echo 'launching ds_proxy in s3 mode listenning on real s3 backend'
  RUST_LOG=debug ./target/release/ds_proxy proxy --address "$DS_PROXY_ADDRESS" --password-file <(echo -n "$PASSWORD") --keyring-file "$KEYRING_FILE" --upstream-url "$UPSTREAM_URL" --s3-access-key "$S3_ACCESS_KEY" --s3-secret-key "$S3_SECRET_KEY" --s3-region "$S3_REGION" > "$DS_PROXY_LOG" 2>&1 &

elif [ "$1" = "fake_s3" ]; then
  echo 'launching ds_proxy in s3 mode listenning on 4444 binded on node server'
  RUST_LOG=info ./target/release/ds_proxy proxy --address "$DS_PROXY_ADDRESS" --password-file <(echo -n "$PASSWORD") --keyring-file "$KEYRING_FILE" --upstream-url "http://localhost:3333" --s3-access-key "$S3_ACCESS_KEY" --s3-secret-key "$S3_SECRET_KEY" --s3-region "eu-west-1" > "$DS_PROXY_LOG" 2>&1 &

else
  echo 'launching ds_proxy listenning on 4444 binded on node server, using redis to emulate write once'
  if nc -z localhost $REDIS_PORT 2>/dev/null; then
    echo 'redis is already running'
  else
    echo "launching redis server on port $REDIS_PORT"
    redis-server --port $REDIS_PORT > /dev/null 2>&1 &
  fi
  RUST_LOG=info,actix-rt=trace,ds_proxy::http::handlers::fetch=trace,ds_proxy::http::handlers::forward=trace ./target/release/ds_proxy proxy --address "$DS_PROXY_ADDRESS" --password-file <(echo -n "$PASSWORD") --keyring-file "$KEYRING_FILE" --upstream-url "http://localhost:3333" --write-once --redis-url "redis://127.0.0.1:$REDIS_PORT"> "$DS_PROXY_LOG" 2>&1 &
fi

echo 'launching fake backend storage with node listenning on 3333'
DEBUG=express:* node tests/fixtures/server-static/server.js > "$NODE_LOG" 2>&1 &

cat << EOF

ds_proxy is now running, and a basic node js server mimics a backend storage.
their logs are $DS_PROXY_LOG and $NODE_LOG

you can add a clear file in the fake storage, and fetch it
curl -X PUT localhost:3333/clear --data-binary @<(echo -n 'I am clear')
cat tests/fixtures/server-static/uploads/clear 
curl localhost:3333/clear

you can encrypt a file by using the ds_proxy, fetch it
curl -X PUT localhost:4444/upstream/cyphered --data-binary @<(echo -n 'What a secret')
curl localhost:4444/upstream/cyphered

you can even try to decrypt the cyphered version by hand
cat tests/fixtures/server-static/uploads/cyphered 
curl localhost:3333/cyphered

EOF

wait
