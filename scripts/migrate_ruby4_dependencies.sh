#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REQUIRED_BUNDLER="4.0.10"

if ! command -v bundle >/dev/null 2>&1; then
  echo "[!] bundler is not installed" >&2
  exit 1
fi

if ! command -v ruby >/dev/null 2>&1; then
  echo "[!] ruby is not installed" >&2
  exit 1
fi

echo "[*] Ruby: $(ruby --version)"
echo "[*] Bundler: $(bundle --version)"

echo "[*] Removing stale bundle artifacts"
rm -rf vendor/bundle .bundle/config Gemfile.lock

echo "[*] Configuring local bundle path"
bundle _${REQUIRED_BUNDLER}_ config set --local path vendor/bundle

echo "[*] Regenerating lockfile for linux"
bundle _${REQUIRED_BUNDLER}_ lock --add-platform x86_64-linux

echo "[*] Installing dependencies"
bundle _${REQUIRED_BUNDLER}_ install

echo "[*] Verifying lockfile metadata"
if ! awk '/^BUNDLED WITH$/ {getline; gsub(/^ +| +$/, "", $0); print $0}' Gemfile.lock | grep -qx "${REQUIRED_BUNDLER}"; then
  echo "[!] Gemfile.lock BUNDLED WITH is not ${REQUIRED_BUNDLER}" >&2
  exit 1
fi

if ! grep -Eq '^  x86_64-linux(-gnu)?$' Gemfile.lock; then
  echo "[!] Gemfile.lock is missing x86_64-linux platform entry" >&2
  exit 1
fi

echo "[*] Running smoke test"
bundle _${REQUIRED_BUNDLER}_ exec ruby bin/evil-ctf.rb --help >/dev/null

echo "[+] Ruby 4.0 dependency migration complete"
