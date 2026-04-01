# WildFly Vault Feature Pack

A Galleon feature pack providing an ability to create WildFly credential store resources backed by an external vendor specific vaults.

## Overview

This project provides a WildFly subsystem extension that enables integration with HashiCorp Vault for secure credential management. It allows WildFly to retrieve credentials and secrets from HashiCorp Vault instead of storing them directly in configuration files.

## Features

- HashiCorp Vault connection management
- Credential store integration with WildFly Elytron
- Support for Vault KV secrets engine
- CLI commands for managing credential stores and aliases
- `${HC_VAULT::…}` expression resolution for secrets (where WildFly resolves expressions outside the MODEL stage)

## Requirements

- Java 17+
- Maven 3.6+
- WildFly 36.0.1.Final or later
- HashiCorp Vault server

## Building

Build the project using Maven:

```bash
mvn clean install
```

## Usage

After building, you can provision a WildFly server with the HashiCorp Vault feature pack using Galleon:

```bash
galleon install org.wildfly.security.vault:wildfly-vault-feature-pack:1.0.0.Alpha3-SNAPSHOT \
  --layers=hashicorp-vault \
  --dir=wildfly
```

Start WildFly with community stability:

```bash
./wildfly/bin/standalone.sh --stability=community
```

### Subsystem configuration (XML)

Minimal HTTP Vault URL:

```xml
<subsystem xmlns="urn:wildfly:hashicorp-vault:community:1.0">
    <credential-store name="my-vault"
                      host-address="http://localhost:8200">
        <credential-reference clear-text="myroot"/>
    </credential-store>
</subsystem>
```

For **HTTPS**, TLS trust and optional client authentication are configured in **Elytron**, not on the credential store. Use **`authentication-context`** with an Elytron client context name:

```xml
<subsystem xmlns="urn:wildfly:hashicorp-vault:community:1.0">
    <credential-store name="secure-vault"
                      host-address="https://vault.example.com:8200"
                      authentication-context="vault-tls-context">
        <credential-reference clear-text="vault-token"/>
    </credential-store>
</subsystem>
```

Optional **`namespace`** (Vault Enterprise) is supported as an attribute on `credential-store`. Define **`vault-tls-context`** (and related Elytron `ssl-context`, `trust-store`, etc.) before referencing it.

### CLI commands

Create Elytron TLS client resources **before** adding a credential store that uses `authentication-context`.

```bash
/subsystem=hashicorp-vault/credential-store=my-vault:add(
    host-address="http://localhost:8200",
    credential-reference={clear-text="myroot"}
)

/subsystem=hashicorp-vault/credential-store=secure-vault:add(
    host-address="https://vault.example.com:8200",
    authentication-context=vault-tls-context,
    credential-reference={clear-text="vault-token"}
)

/subsystem=hashicorp-vault/credential-store=my-vault:add-alias(
    alias="secret/myapp.database_password",
    secret-value="supersecret"
)

# Read aliases
/subsystem=hashicorp-vault/credential-store=my-vault:read-aliases()
```

### Using Vault credentials (`credential-reference`)

Use the credential store **`name`** and an alias in the form **`<vault-path>.<key>`** (KV path and field name):

```xml
<credential-reference store="my-vault" alias="secret/database.password"/>
```

### HC_VAULT expressions

The extension registers an expression resolver. Values can reference Vault using:

```text
${HC_VAULT::credential-store-name:alias}
```

- **`credential-store-name`** — the `name` of the `credential-store` resource
- **`alias`** — the same string as in `credential-reference` (for example `secret/database.password`)

Resolution requires the credential store service to be available and is **not supported in the MODEL stage**; use only on attributes that resolve expressions at a later stage.

Example:

```xml
<system-properties>
    <property name="example.secret" value="${HC_VAULT::my-vault:secret/database.password}"/>
</system-properties>
```

For step-by-step setup, TLS notes, and more examples, see [examples/README.md](examples/README.md).

## Using Podman instead of Docker for testing:

To use Podman instead of Docker on Linux:

Start the Podman daemon in the background:
```bash
$ systemctl --user start podman.socket &
```

Set the DOCKER_HOST environmental variable:
```bash
$ export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
```
See https://podman-desktop.io/tutorial/testcontainers-with-podman for more details.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Contributing

This project is part of the WildFly Security Incubator. Contributions are welcome!
