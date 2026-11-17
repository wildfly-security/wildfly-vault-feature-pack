# HashiCorp Vault Subsystem Examples

## Quick Start

### 1. Start HashiCorp Vault (Development Mode)
```bash
vault server -dev -dev-root-token-id="myroot"
```

### 2. Store Secrets in Vault
```bash
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="myroot"

vault kv put secret/database username=dbuser password=secretpass
```

### 3. Configure WildFly

Add the Vault subsystem to your `standalone.xml`:

```xml
<subsystem xmlns="urn:wildfly:hashicorp-vault:2.0">
    <credential-store name="my-vault"
                      host-address="http://localhost:8200">
        <credential-reference clear-text="myroot"/>
    </credential-store>
</subsystem>
```

For **HTTPS** Vault URLs, TLS trust (and optional client authentication) is configured in Elytron via a `client-ssl-context`. Point `host-address` at `https://…` and set **`client-ssl-context`** to the name of the Elytron `client-ssl-context`:

```xml
<subsystem xmlns="urn:wildfly:hashicorp-vault:2.0">
    <credential-store name="secure-vault"
                      host-address="https://vault.example.com:8200"
                      client-ssl-context="vault-tls-context">
        <credential-reference clear-text="vault-token"/>
    </credential-store>
</subsystem>
```

Define `vault-tls-context` under the Elytron subsystem (`client-ssl-context`, `trust-manager`, `key-store`, etc.) before referencing it.

Optional **`namespace`** sets the Vault Enterprise namespace:

```xml
<credential-store name="namespaced-vault"
                  host-address="https://vault.example.com:8200"
                  namespace="production"
                  client-ssl-context="vault-tls-context">
    <credential-reference clear-text="vault-token"/>
</credential-store>
```

### 4. Use Vault Credentials

Reference Vault credentials in other subsystems using the credential store name and alias format `secret-path?key` (or `@mount#secret-path?key`):

```xml
<subsystem xmlns="urn:jboss:domain:datasources:7.0">
    <datasources>
        <datasource jndi-name="java:jboss/datasources/MyDS" pool-name="MyDS">
            <connection-url>jdbc:postgresql://localhost:5432/mydb</connection-url>
            <driver>postgresql</driver>
            <security>
                <credential-reference store="my-vault" alias="database?password"/>
            </security>
        </datasource>
    </datasources>
</subsystem>
```

### 5. HC_VAULT expressions

The extension registers an **expression resolver** so configuration values can pull secrets from a HashiCorp Vault credential store at runtime.

**Format:**

```text
${HC_VAULT::credential-store-name:alias}
```

- **`credential-store-name`** — the `name` of a `credential-store` under `subsystem=hashicorp-vault`
- **`alias`** — the same alias you would use in `credential-reference` (for example `database?password` or `myapp/database?password`)

**Example** (wherever WildFly resolves expressions in a supported stage, not in the pure management model stage):

```xml
<system-properties>
    <property name="example.secret" value="${HC_VAULT::my-vault:database?password}"/>
</system-properties>
```

If the store or alias is missing, or resolution runs in an unsupported stage, the server reports an expression resolution error. Ensure the Vault credential store is installed and started before those expressions are evaluated.

## CLI Configuration

Configure the credential store using the WildFly CLI:

```bash
$WILDFLY_HOME/bin/jboss-cli.sh --connect

/subsystem=hashicorp-vault/credential-store=my-vault:add(
    host-address="http://localhost:8200",
    credential-reference={clear-text="myroot"}
)

/subsystem=hashicorp-vault/credential-store=secure-vault:add(
    host-address="https://vault.example.com:8200",
    client-ssl-context=vault-tls-context,
    credential-reference={clear-text="vault-token"}
)

/subsystem=hashicorp-vault/credential-store=my-vault:add-alias(
    alias="myapp/database?password",
    secret-value="supersecret"
)
```

Create the Elytron **`vault-tls-context`** (`client-ssl-context`, `trust-manager`, `key-store`, etc.) **before** adding a credential store that references it.

## Alias Format

The credential store uses the format `[engine=TYPE][@mount-path][#]secret-path?key` to map WildFly credential references to Vault secrets:

- `database?password` maps to key `password` in secret `database` under the default mount `secret` (KVv2)
- `myapp/database?password` maps to key `password` in secret `myapp/database` under the default mount `secret`
- `@custom-mount#myapp/database?password` maps to key `password` in secret `myapp/database` under mount `custom-mount`
- `engine=KVv1@secret#myapp?password` explicitly specifies KVv1 engine

The same alias format is used inside **`${HC_VAULT::store:alias}`** expressions.

### Key paths: nested values and special characters

The part after `?` is the key path. An unencoded `/` in it is nested JSON traversal. To refer to a key whose name contains a slash, write the slash as `%2F` (`%2f` is equivalent). The key path is split on `/` first, and each segment is then URL-decoded exactly once:

| Alias key path | Meaning | Looks up |
|----------------|---------|----------|
| `?database/host` | Nested traversal | `data["database"]["host"]` |
| `?database%2Fhost` | Literal key named `database/host` | `data["database/host"]` |
| `?database%252Fhost` | Literal key named `database%2Fhost` | `data["database%2Fhost"]` |

All three can exist in the same secret. `read-aliases` returns aliases in this same encoded form, so every alias it lists can be used again as-is. It lists values inside nested objects by their full key path, but not the objects themselves.

Encode these characters when they are part of a key name or a secret path:

| Character | Write as | Why |
|-----------|----------|-----|
| `%` | `%25` | `%` followed by two hex digits is read as an escape sequence |
| `+` | `%2B` | an unencoded `+` is read as a space |
| space | `%20` | |
| `?` | `%3F` | `?` separates the secret path from the key path |
| `#` | `%23` | |
| `/` | `%2F` | key names only; in a secret path `/` is always a separator |

A key path that ends at a JSON object is not a credential value and does not resolve; use a key path that ends at a value. `add-alias` changes only the value at the key path and leaves sibling keys and their JSON types unchanged, and `remove-alias` removes only that value.

These rules are supported by `wildfly-elytron-hashicorp-vault` version `1.1.0.Final`. See the library's `docs/alias-format.md` for the complete alias specification.

### Legacy alias format

The older `secret-path.key` format is accepted only when Community stability is enabled (`--stability=community`) and is rejected at the default stability. It is kept for compatibility; prefer the format above.

- Trailing dots are discarded, then the alias is split on its **last** dot. `my.app/config` is secret `my` with the literal key `app/config`.
- The first path segment selects the mount: `secret/app.key` addresses secret `app` on mount `secret`. Paths without a slash use the default mount. Use `#path?key` or `@mount#path?key` for an explicit modern alias during migration.
- Legacy keys stay literal: `/`, `%2F`, and `+` are part of the key name. For example, `secret/app.a/b` maps to modern alias `@secret#app?a%2Fb`, while `secret/app.a%2Fb` maps to `@secret#app?a%252Fb`.
- Percent escapes in the secret path follow HTTP path semantics, so `%20` denotes a space and `+` remains a plus. Unescaped `?` and `#` in the path begin a query or fragment; version-selecting queries require legacy support.

These legacy semantics preserve `1.0.1.Final` compatibility. The `1.1.0.CR1` through `CR3` releases decoded legacy keys and treated slashes in them as traversal; check the intended destination when migrating configurations from those releases.
