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

import java.io.IOException;
import java.util.List;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.RunningMode;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.version.Stability;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Credential store integration tests
 */
public class CredentialStoreVaultIntegrationTestCase extends SubsystemJUnit5TestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append("credential-store", CREDENTIAL_STORE_NAME);

    private static VaultContainer<?> vault;

    private KernelServices kernelServices;

    /** Starts Testcontainers Vault once (also from {@link #getSubsystemXml()} when JUnit Platform skips {@code @BeforeClass}). */
    private static synchronized void ensureVaultStarted() {
        if (vault != null) {
            return;
        }
        vault = new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.13"))
                .withVaultToken(VAULT_TOKEN)
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vault.start();
    }

    @BeforeClass
    public static void startVault() {
        ensureVaultStarted();
    }

    @AfterClass
    public static void stopVault() {
        if (vault != null) {
            vault.stop();
            vault = null;
        }
    }

    /**
     * COMMUNITY stability so credential-store resource is registered; NORMAL running mode so
     * performRuntime is invoked when adding/removing credential-stores (required for services to start).
     */
    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.COMMUNITY) {
            @Override
            protected RunningMode getRunningMode() {
                return RunningMode.NORMAL;
            }
        };
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        ensureVaultStarted();
        String hostAddress = vault.getHttpHostAddress();
        return "<subsystem xmlns=\"urn:wildfly:hashicorp-vault:community:1.0\">\n"
                + "    <credential-store name=\"" + CREDENTIAL_STORE_NAME + "\" host-address=\"" + hostAddress + "\">\n"
                + "        <credential-reference clear-text=\"" + VAULT_TOKEN + "\"/>\n"
                + "    </credential-store>\n"
                + "</subsystem>";
    }

    @BeforeEach
    public void bootKernel() throws Exception {
        kernelServices = createKernelServicesBuilder(createAdditionalInitialization())
                .setSubsystemXml(getSubsystemXml())
                .build();
        assertTrue(kernelServices.isSuccessfulBoot(), "Subsystem boot failed: " + kernelServices.getBootError());
        kernelServices.getContainer().awaitStability();
    }

    @Test
    public void testAddNewCredentialStore() throws Exception {
        String newStoreName = "added-store";
        PathAddress newStoreAddress = SUBSYSTEM_ADDRESS.append("credential-store", newStoreName);

        ModelNode add = Util.createAddOperation(newStoreAddress);
        add.get("host-address").set(vault.getHttpHostAddress());
        add.get("credential-reference", "clear-text").set(VAULT_TOKEN);

        ModelNode result = kernelServices.executeOperation(add);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(), "Add credential-store should succeed: " + result);

        kernelServices.getContainer().awaitStability();

        ModelNode readAliases = Util.createOperation("read-aliases", newStoreAddress);
        ModelNode readResult = kernelServices.executeOperation(readAliases);
        assertEquals(SUCCESS, readResult.get(OUTCOME).asString(), "read-aliases on added store should succeed: " + readResult);
        assertNotNull(readResult.get(RESULT).asList());

        ModelNode remove = Util.createRemoveOperation(newStoreAddress);
        ModelNode removeResult = kernelServices.executeOperation(remove);
        assertEquals(SUCCESS, removeResult.get(OUTCOME).asString(), "Remove added credential-store should succeed: " + removeResult);
    }

    @Test
    public void testReadAliasesSucceeds() throws Exception {
        ModelNode op = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        ModelNode result = kernelServices.executeOperation(op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(), "read-aliases should succeed: " + result);
        List<ModelNode> aliases = result.get(RESULT).asList();
        assertNotNull(aliases);
    }

    @Test
    public void testAddAliasReadAliasesRemoveAlias() throws Exception {
        String alias = "secret/integration.test_secret";
        String secretValue = "my-secret-value";

        ModelNode addAlias = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        addAlias.get("alias").set(alias);
        addAlias.get("secret-value").set(secretValue);
        ModelNode addResult = kernelServices.executeOperation(addAlias);
        assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

        ModelNode readAliases = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        readAliases.get("path").set("secret");
        readAliases.get("recursive").set(true);
        ModelNode readResult = kernelServices.executeOperation(readAliases);
        assertEquals(SUCCESS, readResult.get(OUTCOME).asString(), "read-aliases should succeed: " + readResult);
        List<ModelNode> aliasList = readResult.get(RESULT).asList();
        assertNotNull(aliasList);
        assertTrue(aliasList.stream().anyMatch(n -> alias.equals(n.asString())), "Expected alias " + alias + " in " + aliasList);

        ModelNode removeAlias = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
        removeAlias.get("alias").set(alias);
        ModelNode removeResult = kernelServices.executeOperation(removeAlias);
        assertEquals(SUCCESS, removeResult.get(OUTCOME).asString(), "remove-alias should succeed: " + removeResult);

        ModelNode readAfter = kernelServices.executeOperation(readAliases);
        assertEquals(SUCCESS, readAfter.get(OUTCOME).asString(), "read-aliases after remove should succeed: " + readAfter);
        List<ModelNode> afterList = readAfter.get(RESULT).asList();
        assertFalse(afterList != null && afterList.stream().anyMatch(n -> alias.equals(n.asString())), "Expected alias to be removed");
    }

    @Test
    public void testAddMultipleAliasesAndListThem() throws Exception {
        String alias1 = "secret/integration.alias_one";
        String alias2 = "secret/integration.alias_two";
        ModelNode readAliases = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        readAliases.get("path").set("secret");
        readAliases.get("recursive").set(true);

        for (String alias : new String[] { alias1, alias2 }) {
            ModelNode add = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
            add.get("alias").set(alias);
            add.get("secret-value").set("value-" + alias);
            ModelNode r = kernelServices.executeOperation(add);
            assertEquals(SUCCESS, r.get(OUTCOME).asString(), "add-alias " + alias + " should succeed: " + r);
        }

        ModelNode readResult = kernelServices.executeOperation(readAliases);
        assertEquals(SUCCESS, readResult.get(OUTCOME).asString(), "read-aliases should succeed: " + readResult);
        List<ModelNode> list = readResult.get(RESULT).asList();
        assertNotNull(list);
        assertTrue(list.stream().anyMatch(n -> alias1.equals(n.asString())), "Expected " + alias1);
        assertTrue(list.stream().anyMatch(n -> alias2.equals(n.asString())), "Expected " + alias2);

        for (String alias : new String[] { alias1, alias2 }) {
            ModelNode remove = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
            remove.get("alias").set(alias);
            ModelNode r = kernelServices.executeOperation(remove);
            assertEquals(SUCCESS, r.get(OUTCOME).asString(), "remove-alias " + alias + " should succeed: " + r);
        }

        List<ModelNode> afterList = kernelServices.executeOperation(readAliases).get(RESULT).asList();
        assertFalse(afterList != null && afterList.stream().anyMatch(n -> alias1.equals(n.asString())), "Expected alias1 removed");
        assertFalse(afterList != null && afterList.stream().anyMatch(n -> alias2.equals(n.asString())), "Expected alias2 removed");
    }

    // =====================================================================
    // Runtime operation error paths
    // =====================================================================

    /**
     * Adding an alias that already exists in the credential store should fail.
     * Test passes when the second add-alias returns outcome=failed with "already exists" message.
     */
    @Test
    public void testAddAliasThatAlreadyExists() throws Exception {
        String alias = "secret/duplicate.error_test";

        ModelNode addAlias = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        addAlias.get("alias").set(alias);
        addAlias.get("secret-value").set("value1");
        ModelNode firstResult = kernelServices.executeOperation(addAlias);
        assertEquals(SUCCESS, firstResult.get(OUTCOME).asString(), "First add should succeed: " + firstResult);

        ModelNode addDuplicate = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        addDuplicate.get("alias").set(alias);
        addDuplicate.get("secret-value").set("value2");
        ModelNode dupResult = kernelServices.executeOperation(addDuplicate);
        assertEquals("failed", dupResult.get(OUTCOME).asString(), "Duplicate add should fail: " + dupResult);
        assertTrue(dupResult.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                "Should mention 'already exists': " + dupResult.get(FAILURE_DESCRIPTION).asString());

        // Cleanup
        ModelNode removeAlias = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
        removeAlias.get("alias").set(alias);
        kernelServices.executeOperation(removeAlias);
    }

    /**
     * Removing an alias that does not exist in the credential store should fail.
     * Test passes when the operation returns outcome=failed with "does not exist" message.
     */
    @Test
    public void testRemoveAliasThatDoesNotExist() throws Exception {
        ModelNode removeAlias = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
        removeAlias.get("alias").set("secret/nonexistent.no_such_key");
        ModelNode result = kernelServices.executeOperation(removeAlias);
        assertEquals("failed", result.get(OUTCOME).asString(), "Remove of non-existent alias should fail: " + result);
        assertTrue(result.get(FAILURE_DESCRIPTION).asString().contains("does not exist"),
                "Should mention 'does not exist': " + result.get(FAILURE_DESCRIPTION).asString());
    }

    /**
     * Adding an alias without providing a secret-value should fail.
     * Test passes when the operation returns outcome=failed.
     */
    @Test
    public void testAddAliasWithoutSecretValue() throws Exception {
        ModelNode addAlias = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        addAlias.get("alias").set("secret/missing.secret_value");
        // Deliberately omit secret-value
        ModelNode result = kernelServices.executeOperation(addAlias);
        assertEquals("failed", result.get(OUTCOME).asString(),
                "add-alias without secret-value should fail: " + result);
    }
}
