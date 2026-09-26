# Extension Model

The Preview extension protocol loads metadata from validated TOML manifests. It intentionally does not execute arbitrary third-party plugin code.

Example manifest:

~~~toml
schema_version = 1
id = "io.example.gitleaks"
name = "Gitleaks"
version = "1.0.0"

[scanner]
executable = "gitleaks"

[output]
format = "sarif"

[capabilities]
sast = false
secrets = true
sca = false
iac = false

[license]
spdx = "MIT"
bundled = false
~~~

Validation requires schema version 1, reverse-DNS identifier style, non-empty name and version, a command-name-only executable value, sarif or json output, and an SPDX license identifier.

Future extension roles are reserved for Scanner Provider, Enricher, Renderer, Importer, and Exporter. A future runtime must add explicit permission and trust decisions before any executable code is enabled.
