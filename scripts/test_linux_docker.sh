#!/usr/bin/env bash
# Offline runtime verification. Images must be prepared locally beforehand.
# No image pulls, builds, installs, container deletion or host configuration changes.
set -u
set -o pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v docker >/dev/null 2>&1; then
    echo 'Debian, Fedora, Arch: NOT RUN (Docker CLI unavailable).'
    exit 2
fi
if ! docker info >/dev/null 2>&1; then
    echo 'Debian, Fedora, Arch: NOT RUN (Docker daemon unavailable).'
    exit 2
fi

failures=0
for family in debian fedora arch; do
    case "$family" in
        debian) image="${DIALTONE_DEBIAN_IMAGE:-dialtone-watcher-test:debian}"; manager=dpkg ;;
        fedora) image="${DIALTONE_FEDORA_IMAGE:-dialtone-watcher-test:fedora}"; manager=rpm ;;
        arch) image="${DIALTONE_ARCH_IMAGE:-dialtone-watcher-test:arch}"; manager=pacman ;;
    esac
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "$family: NOT RUN (local test image unavailable: $image)."
        failures=$((failures + 1))
        continue
    fi
    # No --rm: user safety rules prohibit deleting containers. Docker prints
    # the ID below; retain it for the user's own inspection and lifecycle policy.
    container_id="$(docker create --pull=never --network=none --read-only \
        --mount "type=bind,source=$project_dir,target=/workspace,readonly" \
        --tmpfs /tmp:rw,nosuid,nodev --workdir /workspace \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --env HOME=/tmp/dialtone-home \
        --env "DIALTONE_EXPECT_PACKAGE_MANAGER=$manager" \
        "$image" python3 -m pytest -q -s -p no:cacheprovider \
        -m linux_integration tests/test_linux.py)" || {
        echo "$family: FAILED (container could not be created)."
        failures=$((failures + 1))
        continue
    }
    echo "$family: retained container $container_id"
    if ! docker start --attach "$container_id"; then
        echo "$family: FAILED (container start or attachment failed)."
        failures=$((failures + 1))
        continue
    fi
    # docker start --attach does not reliably propagate the container exit code.
    test_exit="$(docker inspect --format '{{.State.ExitCode}}' "$container_id")" || test_exit=1
    if [[ "$test_exit" != 0 ]]; then
        echo "$family: FAILED (test exit $test_exit)."
        failures=$((failures + 1))
    else
        echo "$family: PASSED."
    fi
done
if [[ "$failures" != 0 ]]; then
    exit 1
fi
