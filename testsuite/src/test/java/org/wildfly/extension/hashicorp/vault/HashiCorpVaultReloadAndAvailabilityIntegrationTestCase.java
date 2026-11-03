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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.extension.hashicorp.vault.CredentialStoreDefinition.HOST_ADDRESS;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit5.ArquillianExtension;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.as.arquillian.api.ServerSetup;
import org.jboss.as.arquillian.api.ServerSetupTask;
import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

import com.github.dockerjava.api.DockerClient;

/**
 * Integration test for credential store behavior across server reload and Vault unavailability.
 * <p>
 * Validates that the credential store survives server reload, that operations fail with a
 * recognizable error ({@code ELYHCVT0034}) when Vault is unreachable without leaking the token,
 * that operations recover without server restart once Vault becomes available again, and that
 * the lazy initialization allows credential store add to succeed even when Vault is down.
 */
@ExtendWith(ArquillianExtension.class)
@RunAsClient
@ServerSetup(HashiCorpVaultReloadAndAvailabilityIntegrationTestCase.VaultSetup.class)
public class HashiCorpVaultReloadAndAvailabilityIntegrationTestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final int VAULT_PORT = 8200;
    private static final String CREDENTIAL_STORE_NAME = "vault-reload-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append(
            "credential-store", CREDENTIAL_STORE_NAME);

    private static final String ATTR_ALIAS = CredentialStoreDefinition.ALIAS.getName();
    private static final String ATTR_SECRET_VALUE = CredentialStoreDefinition.SECRET_VALUE.getName();
    private static final String ATTR_PATH = CredentialStoreDefinition.PATH.getName();
    private static final String ATTR_RECURSIVE = CredentialStoreDefinition.RECURSIVE.getName();

    /** Error code for "All login strategies failed" — expected when Vault is unreachable. */
    private static final String ELYHCVT0034 = "ELYHCVT0034";

    private static final long RELOAD_TIMEOUT_MILLIS = 60_000;
    private static final long RELOAD_POLL_INTERVAL_MILLIS = 500;

    private static VaultContainer<?> vault;

    @Deployment
    public static JavaArchive deployment() {
        return ShrinkWrap.create(JavaArchive.class, "vault-reload-availability-test.jar");
    }

    // =====================================================================
    // Reload tests
    // =====================================================================

    /**
     * Stores an alias, reloads the server, then reads the alias back.
     * <p><b>Passes when:</b> {@code add-alias} succeeds before reload, and {@code read-aliases}
     * after reload succeeds with {@code outcome=success} and returns a list containing the stored alias.
     */
    @Test
    public void testCredentialStoreWorksAfterReload(@ArquillianResource ManagementClient managementClient) throws Exception {
        String alias = "#reload?survives_reload";

        addAlias(managementClient, CREDENTIAL_STORE_ADDRESS, alias, "reload-test-value");
        try {
            reloadServer(managementClient);

            List<ModelNode> aliases = readAliases(managementClient, CREDENTIAL_STORE_ADDRESS);
            assertNotNull(aliases, "Alias list should not be null after reload");
            assertTrue(aliases.stream().anyMatch(n -> alias.equals(n.asString())),
                    "Alias '" + alias + "' should survive reload, got: " + aliases);
        } finally {
            removeAlias(managementClient, CREDENTIAL_STORE_ADDRESS, alias);
        }
    }

    // =====================================================================
    // Vault unavailability tests
    // =====================================================================

    /**
     * Stops the Vault container, reloads the server to force a fresh connector, then verifies
     * that {@code add-alias} fails with a recognizable error. After restarting Vault, verifies
     * that {@code read-aliases} succeeds again without a server restart.
     * <p><b>Passes when:</b> {@code add-alias} with Vault stopped fails with {@code outcome=failed}
     * and the failure description contains {@code ELYHCVT0034} but not the Vault token value, and
     * {@code read-aliases} after restarting Vault and reloading succeeds with {@code outcome=success}.
     */
    @Test
    public void testOperationsFailWhenVaultUnavailable(@ArquillianResource ManagementClient managementClient) throws Exception {
        stopVault();
        try {
            // Reload to force a fresh connector (clears any cached connection)
            reloadServer(managementClient);
            assertOperationFailsWithVaultDown(managementClient, CREDENTIAL_STORE_ADDRESS);
        } finally {
            startVault();
        }

        // Reload to get a clean connector state, then verify recovery
        reloadServer(managementClient);
        List<ModelNode> aliases = readAliases(managementClient, CREDENTIAL_STORE_ADDRESS);
        assertNotNull(aliases, "read-aliases should succeed after Vault recovers");
    }

    /**
     * Stops Vault container, adds a second credential store, and verifies that the add succeeds
     * (lazy initialization — {@code VaultConnector.configure()} does not contact Vault) while the
     * first write operation on it fails. After restarting Vault, verifies the store becomes
     * functional without re-adding it.
     * <p><b>Passes when:</b> {@code credential-store:add} with Vault stopped succeeds with
     * {@code outcome=success}, the subsequent {@code add-alias} fails with {@code ELYHCVT0034}
     * and without leaking the token, and {@code read-aliases} after restarting Vault succeeds with
     * {@code outcome=success}.
     */
    @Test
    public void testCredentialStoreAddSucceedsWithVaultDown(@ArquillianResource ManagementClient managementClient) throws Exception {
        String secondStoreName = "vault-lazy-store";
        PathAddress secondStoreAddress = SUBSYSTEM_ADDRESS.append("credential-store", secondStoreName);

        String vaultAddress = vault.getHttpHostAddress();
        stopVault();
        try {
            // Add should succeed — VaultConnector.configure() is a no-op, no Vault contact at add time
            ModelNode add = Util.createAddOperation(secondStoreAddress);
            add.get(HOST_ADDRESS).set(vaultAddress);
            add.get("credential-reference", "clear-text").set(VAULT_TOKEN);
            VaultHttpsElytronSetup.executeSuccess(managementClient, add);

            // First operation triggers actual login — should fail
            assertOperationFailsWithVaultDown(managementClient, secondStoreAddress);
        } finally {
            startVault();
        }

        try {
            // Recovery — same store should work without re-adding
            List<ModelNode> aliases = readAliases(managementClient, secondStoreAddress);
            assertNotNull(aliases, "read-aliases should succeed after Vault recovers");
        } finally {
            ModelNode remove = Util.createRemoveOperation(secondStoreAddress);
            remove.get("operation-headers", "allow-resource-service-restart").set(true);
            executeOperation(managementClient, remove);
        }
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static ModelNode executeOperation(ManagementClient client, ModelNode operation) throws IOException {
        return client.getControllerClient().execute(operation);
    }

    private static void addAlias(ManagementClient client, PathAddress storeAddress,
                                 String alias, String secretValue) {
        ModelNode op = Util.createOperation("add-alias", storeAddress);
        op.get(ATTR_ALIAS).set(alias);
        op.get(ATTR_SECRET_VALUE).set(secretValue);
        VaultHttpsElytronSetup.executeSuccess(client, op);
    }

    private static void removeAlias(ManagementClient client, PathAddress storeAddress,
                                    String alias) throws IOException {
        ModelNode op = Util.createOperation("remove-alias", storeAddress);
        op.get(ATTR_ALIAS).set(alias);
        executeOperation(client, op);
    }

    private static List<ModelNode> readAliases(ManagementClient client,
                                               PathAddress storeAddress) throws IOException {
        ModelNode op = Util.createOperation("read-aliases", storeAddress);
        op.get(ATTR_PATH).set("");
        op.get(ATTR_RECURSIVE).set(true);
        ModelNode result = executeOperation(client, op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(), "read-aliases should succeed: " + result);
        return result.get(RESULT).asList();
    }

    /**
     * Asserts that {@code add-alias} fails with {@code ELYHCVT0034} and does not leak the Vault token.
     * Uses {@code add-alias} rather than {@code read-aliases} because an empty {@code read-aliases}
     * can succeed without contacting Vault when no secrets exist at the root path.
     */
    private static void assertOperationFailsWithVaultDown(ManagementClient client,
                                                          PathAddress storeAddress) throws IOException {
        ModelNode op = Util.createOperation("add-alias", storeAddress);
        op.get(ATTR_ALIAS).set("#unavailability-probe?probe_key");
        op.get(ATTR_SECRET_VALUE).set("probe-value");
        ModelNode result = executeOperation(client, op);
        assertEquals("failed", result.get(OUTCOME).asString(),
                "add-alias should fail when Vault is unreachable: " + result);

        String failureDescription = result.get(FAILURE_DESCRIPTION).asString();
        assertTrue(failureDescription.contains(ELYHCVT0034),
                "Failure should contain '" + ELYHCVT0034 + "': " + failureDescription);
        assertFalse(failureDescription.contains(VAULT_TOKEN),
                "Failure message must not leak the Vault token: " + failureDescription);
    }

    private static void stopVault() {
        DockerClient client = DockerClientFactory.instance().client();
        client.stopContainerCmd(vault.getContainerId()).withTimeout(1).exec();
    }

    private static void startVault() {
        DockerClient client = DockerClientFactory.instance().client();
        client.startContainerCmd(vault.getContainerId()).exec();
        // The Docker start API returns before Vault is ready to accept requests.
        Wait.forHttp("/v1/sys/health")
                .forPort(VAULT_PORT)
                .forStatusCode(200)
                .withStartupTimeout(Duration.ofSeconds(60))
                .waitUntilReady(vault);
    }

    /**
     * Reloads the WildFly server and waits until it reaches {@code running} state.
     * Creates a fresh {@link ModelControllerClient} for each poll iteration to avoid
     * stale connections after the management port restarts during reload (follows the
     * same pattern as WildFly's {@code ServerReload.waitForLiveServerToReload}).
     */
    private static void reloadServer(ManagementClient managementClient) throws Exception {
        ModelNode reloadOp = Util.createOperation("reload", PathAddress.EMPTY_ADDRESS);
        try {
            managementClient.getControllerClient().execute(reloadOp);
        } catch (IOException e) {
            final Throwable cause = e.getCause();
            if (!(cause instanceof ExecutionException) && !(cause instanceof CancellationException)) {
                throw e;
            }
        }

        String address = managementClient.getMgmtAddress();
        int port = managementClient.getMgmtPort();

        ModelNode readStateOp = Util.createOperation("read-attribute", PathAddress.EMPTY_ADDRESS);
        readStateOp.get("name").set("server-state");

        long deadline = System.currentTimeMillis() + RELOAD_TIMEOUT_MILLIS;
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(RELOAD_POLL_INTERVAL_MILLIS);
            try (ModelControllerClient client = ModelControllerClient.Factory.create(address, port)) {
                ModelNode result = client.execute(readStateOp);
                if ("running".equals(result.get(RESULT).asString())) {
                    return;
                }
            } catch (IOException ignored) {
            }
        }
        throw new AssertionError("Server did not reach 'running' state within "
                + RELOAD_TIMEOUT_MILLIS / 1000 + " seconds after reload");
    }

    // =====================================================================
    // Server setup
    // =====================================================================

    /**
     * Starts a HashiCorp Vault container and adds a credential-store resource to the running
     * WildFly server before tests execute, then removes the store and stops Vault after all tests
     * complete. Unavailability tests use container stop/start via the Docker API.
     */
    public static final class VaultSetup implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            int hostPort;
            try (ServerSocket socket = new ServerSocket(0)) {
                hostPort = socket.getLocalPort();
            }
            vault = new VaultContainer<>(DockerImageName.parse(VaultImages.VAULT))
                    .withVaultToken(VAULT_TOKEN);
            // Docker can reassign a random host port on restart. Keep the endpoint used
            // by WildFly unchanged throughout the availability tests.
            vault.setPortBindings(List.of(hostPort + ":" + VAULT_PORT));
            vault.start();

            ModelNode add = Util.createAddOperation(CREDENTIAL_STORE_ADDRESS);
            add.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
            add.get("credential-reference", "clear-text").set(VAULT_TOKEN);
            VaultHttpsElytronSetup.executeSuccess(managementClient, add);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            try {
                // Restart in case a test failed before its finally block
                if (vault != null) {
                    try {
                        startVault();
                    } catch (Exception ignored) {
                        // Container may already be running or stopped
                    }
                }
                ModelNode remove = Util.createRemoveOperation(CREDENTIAL_STORE_ADDRESS);
                remove.get("operation-headers", "allow-resource-service-restart").set(true);
                managementClient.getControllerClient().execute(remove);
            } finally {
                if (vault != null) {
                    vault.stop();
                }
            }
        }
    }
}
