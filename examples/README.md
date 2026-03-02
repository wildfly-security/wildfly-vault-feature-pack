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

For production environments with TLS, configure certificate stores:

```xml
<subsystem xmlns="urn:wildfly:hashicorp-vault:community:1.0">
    <credential-store name="secure-vault"
                      host-address="https://vault.example.com:8200"
                      truststore-path="/opt/security/truststore.jks"
                      keystore-path="/opt/security/keystore.jks"
                      truststore-password="keystore-password">
        <credential-reference clear-text="vault-token"/>
    </credential-store>
</subsystem>
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
    truststore-path="/opt/security/truststore.jks",
    keystore-path="/opt/security/keystore.jks",
    truststore-password="keystore-password",
    credential-reference={clear-text="vault-token"}
)

/subsystem=hashicorp-vault/credential-store=my-vault:add-alias(
    alias="secret/myapp.database_password",
    secret-value="supersecret"
)
```

## Alias Format

The credential store uses the format `<vault-path>.<key>` to map WildFly credential references to Vault secrets:
- `secret/database.password` maps to the `password` key in the `secret/database` path in Vault
- `secret/myapp.database_password` maps to the `database_password` key in the `secret/myapp` path
