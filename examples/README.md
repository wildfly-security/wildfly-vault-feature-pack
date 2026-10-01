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
