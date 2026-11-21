"""Build the gateway on the disposable Actions checkout for X-M02-2."""

import os
from pathlib import Path
import subprocess

source = Path("crates/application/src/oauth.rs")
build = ["cargo", "build", "--locked", "-p", "humaux-gateway"]
if os.environ["OAUTH_CLIENT_FAULT"] == "pkce":
    # Compile the mutation only on the runner. Restore the checkout even on failure.
    original = source.read_text()
    check = "if !s256_matches(verifier, consumed.pkce_challenge) {"
    assert original.count(check) == 1
    try:
        source.write_text(original.replace(check, "if false && !s256_matches(verifier, consumed.pkce_challenge) {"))
        subprocess.run(build, check=True)
    finally:
        source.write_text(original)
else:
    subprocess.run(build, check=True)
