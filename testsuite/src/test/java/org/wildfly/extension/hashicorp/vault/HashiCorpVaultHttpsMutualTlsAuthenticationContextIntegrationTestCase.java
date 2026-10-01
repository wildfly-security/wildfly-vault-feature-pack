/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILURE_DESCRIPTION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.utility.MountableFile;

/**
 * Elytron authentication-context with {@code ssl-context} match-rules and mutual TLS to Vault (HTTPS listener requires client certificate).
 */
@ExtendWith(ArquillianExtension.class)
@RunAsClient
@ServerSetup(HashiCorpVaultHttpsMutualTlsAuthenticationContextIntegrationTestCase.ElytronSetup.class)
public class HashiCorpVaultHttpsMutualTlsAuthenticationContextIntegrationTestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-mtls-store";
    private static final String CERT_AUTH_STORE_NAME = "vault-cert-auth-store";
    private static final String CERT_AUTH_CONTAINER_PATH = "/vault/certs/client-auth.crt";
    private static final String CERT_AUTH_ROLE = "wildfly";
    private static final String CERT_AUTH_POLICY = "admin";
    private static final VaultHttpsElytronSetup.SetupNames NAMES = VaultHttpsElytronSetup.SetupNames.mutualTls();

    private static final VaultContainerHttps<?> VAULT;

    static {
        try {
            VAULT = new VaultContainerHttps<>("hashicorp/vault:1.21", true);
            VAULT.withVaultToken(VAULT_TOKEN).withInitCommand(
                    "secrets enable kv-v2",
                    "kv put secret/testing1 top_secret=password123"
            );
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Deployment
    public static JavaArchive deployment() {
        return ShrinkWrap.create(JavaArchive.class, "vault-https-mtls-auth-context-test.jar");
    }

    /**
     * Adds a HashiCorp Vault credential store over HTTPS where Vault requires mutual TLS, using the matching Elytron
     * {@code authentication-context}, then removes it.
     * <p><b>Passes when:</b> both management operations ({@code add} and {@code remove} for the credential-store) complete
     * with {@code outcome=success} (no exception from {@link VaultHttpsElytronSetup#executeSuccess}).
     */
    @Test
    public void testCredentialStoreWithAuthenticationContextOverMutualTlsHttps(@ArquillianResource ManagementClient managementClient) {
        PathAddress storeAddress = PathAddress.pathAddress(PathElement.pathElement("subsystem", "hashicorp-vault"))
                .append("credential-store", CREDENTIAL_STORE_NAME);

        ModelNode add = Util.createAddOperation(storeAddress);
        add.get("host-address").set(VAULT.composeHttpsHostAddress());
        add.get("client-ssl-context").set(NAMES.sslContext);
        add.get("credential-reference", "clear-text").set(VAULT_TOKEN);

        VaultHttpsElytronSetup.executeSuccess(managementClient, add);

        ModelNode remove = Util.createRemoveOperation(storeAddress);
        remove.get("operation-headers", "allow-resource-service-restart").set(true);
        VaultHttpsElytronSetup.executeSuccess(managementClient, remove);
    }

    /**
     * Credential store with TLS certificate authentication (no {@code credential-reference}).
     * The client certificate from the Elytron {@code authentication-context} authenticates to Vault directly
     * via the {@code cert} auth method.
     * <p><b>Passes when:</b> credential store add, add-alias, read-aliases, remove-alias, and credential store
     * remove all complete with {@code outcome=success}.
     */
    @Test
    public void testCredentialStoreWithCertAuthNoToken(@ArquillianResource ManagementClient managementClient) throws IOException {
        PathAddress storeAddress = PathAddress.pathAddress(PathElement.pathElement("subsystem", "hashicorp-vault"))
                .append("credential-store", CERT_AUTH_STORE_NAME);

        ModelNode add = Util.createAddOperation(storeAddress);
        add.get("host-address").set(VAULT.composeHttpsHostAddress());
        add.get("client-ssl-context").set(NAMES.sslContext);
        VaultHttpsElytronSetup.executeSuccess(managementClient, add);

        String alias = "certtest?password";
        String normalizedAlias = "#" + alias;  // read-aliases returns normalized format: #secretPath?key
        ModelNode addAlias = Util.createOperation("add-alias", storeAddress);
        addAlias.get("alias").set(alias);
        addAlias.get("secret-value").set("s3cr3t");
        VaultHttpsElytronSetup.executeSuccess(managementClient, addAlias);

        ModelNode readAliases = Util.createOperation("read-aliases", storeAddress);
        readAliases.get("path").set("");  // Empty path = list all aliases
        readAliases.get("recursive").set(true);
        ModelNode readResult = managementClient.getControllerClient().execute(readAliases);
        assertEquals(SUCCESS, readResult.get(OUTCOME).asString(), "read-aliases should succeed: " + readResult);
        List<ModelNode> aliases = readResult.get(RESULT).asList();
        assertTrue(aliases.stream().anyMatch(n -> normalizedAlias.equals(n.asString())),
                "Expected alias '" + normalizedAlias + "' in read-aliases result, got: " + aliases);

        ModelNode removeAlias = Util.createOperation("remove-alias", storeAddress);
        removeAlias.get("alias").set(alias);  // Use the new format alias
        VaultHttpsElytronSetup.executeSuccess(managementClient, removeAlias);

        ModelNode remove = Util.createRemoveOperation(storeAddress);
        remove.get("operation-headers", "allow-resource-service-restart").set(true);
        VaultHttpsElytronSetup.executeSuccess(managementClient, remove);
    }

    /**
     * Credential store without token and without cert auth enabled on Vault.
     * The client certificate is presented at the TLS level but Vault has no {@code cert} auth method,
     * so all login strategies fail.
     * <p>The credential store add succeeds because Vault connections are created lazily.
     * Authentication failure is detected on the first operation that contacts Vault.
     * <p><b>Passes when:</b> the first vault operation after add fails with "All login strategies failed".
     */
    @Test
    public void testCredentialStoreWithoutTokenFailsWhenCertAuthNotEnabled(@ArquillianResource ManagementClient managementClient) throws Exception {
        VAULT.execInContainer("vault", "auth", "disable", "cert");

        PathAddress storeAddress = PathAddress.pathAddress(PathElement.pathElement("subsystem", "hashicorp-vault"))
                .append("credential-store", "vault-no-auth-store");
        try {
            ModelNode add = Util.createAddOperation(storeAddress);
            add.get("host-address").set(VAULT.composeHttpsHostAddress());
            add.get("client-ssl-context").set(NAMES.sslContext);

            ModelNode addResponse = managementClient.getControllerClient().execute(add);
            assertEquals(SUCCESS, addResponse.get(OUTCOME).asString(),
                    "Credential store add should succeed (connections are lazy): " + addResponse);

            ModelNode readAliases = Util.createOperation("read-aliases", storeAddress);
            readAliases.get("path").set("#");
            readAliases.get("recursive").set(true);
            ModelNode response = managementClient.getControllerClient().execute(readAliases);
            assertNotEquals(SUCCESS, response.get(OUTCOME).asString(),
                    "First vault operation should fail without token and without cert auth enabled on Vault");
            assertTrue(response.get(FAILURE_DESCRIPTION).toString().contains("All login strategies failed"),
                    "Expected 'All login strategies failed' in failure description, got: " + response.get(FAILURE_DESCRIPTION));
        } finally {
            ModelNode cleanup = Util.createRemoveOperation(storeAddress);
            cleanup.get("operation-headers", "allow-resource-service-restart").set(true);
            try { managementClient.getControllerClient().execute(cleanup); } catch (Exception ignored) { }

            enableVaultCertAuth();
        }
    }

    private static void enableVaultCertAuth() throws Exception {
        // Disable first to make this idempotent (ignore errors if not enabled)
        VAULT.execInContainer("vault", "auth", "disable", "cert");
        VAULT.execInContainer("vault", "auth", "enable", "cert");
        VAULT.execInContainer("vault", "write", "auth/cert/certs/" + CERT_AUTH_ROLE,
                "display_name=" + CERT_AUTH_ROLE, "policies=" + CERT_AUTH_POLICY,
                "certificate=@" + CERT_AUTH_CONTAINER_PATH);
    }

    public static final class ElytronSetup implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            if (!VAULT.isRunning()) {
                VAULT.start();
            }
            Path clientCert = VAULT.getClientCertificateFiles().clientCertFile();
            VAULT.copyFileToContainer(
                    MountableFile.forHostPath(clientCert, 0644),
                    CERT_AUTH_CONTAINER_PATH);
            enableVaultCertAuth();
            VaultHttpsElytronSetup.install(managementClient, VAULT, NAMES, true);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            VaultHttpsElytronSetup.tearDown(managementClient, NAMES, true);
            VAULT.stop();
        }
    }
}
