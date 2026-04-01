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
<subsystem xmlns="urn:wildfly:hashicorp-vault:community:1.0">
    <credential-store name="my-vault"
                      host-address="http://localhost:8200">
        <credential-reference clear-text="myroot"/>
    </credential-store>
</subsystem>
```

For **HTTPS** Vault URLs, TLS trust (and optional client authentication) is **not** configured on the credential store itself. Point `host-address` at `https://…` and set **`authentication-context`** to the name of an Elytron **authentication-context** that defines how the management/client SSL connection to Vault is secured (trust store, client certificate, etc.):

```xml
<subsystem xmlns="urn:wildfly:hashicorp-vault:community:1.0">
    <credential-store name="secure-vault"
                      host-address="https://vault.example.com:8200"
                      authentication-context="vault-tls-context">
        <credential-reference clear-text="vault-token"/>
    </credential-store>
</subsystem>
```

Define `vault-tls-context` under the Elytron subsystem (for example with a `trust-store` and `ssl-context` referenced from that authentication context). The exact Elytron resources depend on your PKI layout; see WildFly documentation for **authentication-context** and **client-ssl-context**.

Optional **`namespace`** sets the Vault Enterprise namespace:

```xml
<credential-store name="namespaced-vault"
                  host-address="https://vault.example.com:8200"
                  namespace="production"
                  authentication-context="vault-tls-context">
    <credential-reference clear-text="vault-token"/>
</credential-store>
```

### 4. Use Vault Credentials

Reference Vault credentials in other subsystems using the credential store name and alias format `<vault-path>.<key>`:

```xml
<subsystem xmlns="urn:jboss:domain:datasources:7.0">
    <datasources>
        <datasource jndi-name="java:jboss/datasources/MyDS" pool-name="MyDS">
            <connection-url>jdbc:postgresql://localhost:5432/mydb</connection-url>
            <driver>postgresql</driver>
            <security>
                <credential-reference store="my-vault" alias="secret/database.password"/>
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
- **`alias`** — the same alias you would use in `credential-reference` (for example `secret/database.password` for KV path `secret/database`, key `password`)

**Example** (wherever WildFly resolves expressions in a supported stage, not in the pure management model stage):

```xml
<system-properties>
    <property name="example.secret" value="${HC_VAULT::my-vault:secret/database.password}"/>
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
    authentication-context=vault-tls-context,
    credential-reference={clear-text="vault-token"}
)

/subsystem=hashicorp-vault/credential-store=my-vault:add-alias(
    alias="secret/myapp.database_password",
    secret-value="supersecret"
)
```

Create the Elytron **`vault-tls-context`** (and related `ssl-context`, `trust-store`, etc.) **before** adding a credential store that references it.

## Alias Format

The credential store uses the format `<vault-path>.<key>` to map WildFly credential references to Vault secrets:

- `secret/database.password` maps to the `password` key in the `secret/database` path in Vault
- `secret/myapp.database_password` maps to the `database_password` key in the `secret/myapp` path in Vault

The same alias form is used inside **`${HC_VAULT::store:alias}`** expressions.
