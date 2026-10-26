# Optional preparation step only; the test runner never builds or downloads.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-psutil python3-pytest
