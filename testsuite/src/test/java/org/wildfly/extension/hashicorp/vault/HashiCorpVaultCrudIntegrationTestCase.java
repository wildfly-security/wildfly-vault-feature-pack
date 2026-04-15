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
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * End-to-end Arquillian integration test that exercises the full credential store CRUD lifecycle against a real
 * WildFly server provisioned with the hashicorp-vault feature pack, backed by a Testcontainers Vault instance.
 * <p>
 * Covers the user workflow: provision WildFly with feature pack &rarr; add credential store &rarr;
 * add/read/remove aliases &rarr; resolve expressions &rarr; error handling for duplicates and missing aliases.
 */
@ExtendWith(ArquillianExtension.class)
@RunAsClient
@ServerSetup(HashiCorpVaultCrudIntegrationTestCase.VaultSetup.class)
public class HashiCorpVaultCrudIntegrationTestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-crud-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append(
            "credential-store", CREDENTIAL_STORE_NAME);

    // Operation names (private in CredentialStoreDefinition, so duplicated here)
    private static final String OP_ADD_ALIAS = "add-alias";
    private static final String OP_REMOVE_ALIAS = "remove-alias";
    private static final String OP_READ_ALIASES = "read-aliases";
    private static final String OP_RESOLVE_EXPRESSION = "resolve-expression";

    // Attribute names from CredentialStoreDefinition
    private static final String ATTR_ALIAS = CredentialStoreDefinition.ALIAS.getName();
    private static final String ATTR_SECRET_VALUE = CredentialStoreDefinition.SECRET_VALUE.getName();
    private static final String ATTR_PATH = CredentialStoreDefinition.PATH.getName();
    private static final String ATTR_RECURSIVE = CredentialStoreDefinition.RECURSIVE.getName();

    private static VaultContainer<?> vault;

    @Deployment
    public static JavaArchive deployment() {
        return ShrinkWrap.create(JavaArchive.class, "vault-crud-test.jar");
    }

    // =====================================================================
    // Full CRUD lifecycle
    // =====================================================================

    /**
     * Exercises the complete alias lifecycle: adds an alias with a secret value, reads aliases to confirm it is present,
     * removes the alias, and reads aliases again to confirm removal.
     */
    @Test
    public void testFullCrudLifecycle(@ArquillianResource ManagementClient managementClient) throws IOException {
        String alias = "secret/crud.lifecycle_secret";
        String secretValue = "test-lifecycle-value-123";

        ModelNode addAlias = Util.createOperation(OP_ADD_ALIAS, CREDENTIAL_STORE_ADDRESS);
        addAlias.get(ATTR_ALIAS).set(alias);
        addAlias.get(ATTR_SECRET_VALUE).set(secretValue);
        ModelNode addResult = executeOperation(managementClient, addAlias);
        assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

        ModelNode readAliases = Util.createOperation(OP_READ_ALIASES, CREDENTIAL_STORE_ADDRESS);
        readAliases.get(ATTR_PATH).set("secret");
        readAliases.get(ATTR_RECURSIVE).set(true);
        ModelNode readResult = executeOperation(managementClient, readAliases);
        assertEquals(SUCCESS, readResult.get(OUTCOME).asString(), "read-aliases should succeed: " + readResult);
        List<ModelNode> aliases = readResult.get(RESULT).asList();
        assertNotNull(aliases, "Alias list should not be null");
        assertTrue(aliases.stream().anyMatch(n -> alias.equals(n.asString())),
                "Expected alias '" + alias + "' to be present after add, got: " + aliases);

        ModelNode removeAlias = Util.createOperation(OP_REMOVE_ALIAS, CREDENTIAL_STORE_ADDRESS);
        removeAlias.get(ATTR_ALIAS).set(alias);
        ModelNode removeResult = executeOperation(managementClient, removeAlias);
        assertEquals(SUCCESS, removeResult.get(OUTCOME).asString(), "remove-alias should succeed: " + removeResult);

        ModelNode readAfter = executeOperation(managementClient, readAliases);
        assertEquals(SUCCESS, readAfter.get(OUTCOME).asString(), "read-aliases after remove should succeed: " + readAfter);
        List<ModelNode> afterList = readAfter.get(RESULT).asList();
        assertFalse(afterList != null && afterList.stream().anyMatch(n -> alias.equals(n.asString())),
                "Alias should no longer be present after removal");
    }

    /**
     * Adds multiple aliases, verifies all are listed, removes them, and verifies the list is clean.
     */
    @Test
    public void testAddMultipleAliasesAndListThem(@ArquillianResource ManagementClient managementClient) throws IOException {
        String alias1 = "secret/crud.multi_one";
        String alias2 = "secret/crud.multi_two";

        for (String alias : new String[] { alias1, alias2 }) {
            ModelNode add = Util.createOperation(OP_ADD_ALIAS, CREDENTIAL_STORE_ADDRESS);
            add.get(ATTR_ALIAS).set(alias);
            add.get(ATTR_SECRET_VALUE).set("value-" + alias);
            ModelNode r = executeOperation(managementClient, add);
            assertEquals(SUCCESS, r.get(OUTCOME).asString(), "add-alias " + alias + " should succeed: " + r);
        }

        ModelNode readAliases = Util.createOperation(OP_READ_ALIASES, CREDENTIAL_STORE_ADDRESS);
        readAliases.get(ATTR_PATH).set("secret");
        readAliases.get(ATTR_RECURSIVE).set(true);
        ModelNode readResult = executeOperation(managementClient, readAliases);
        assertEquals(SUCCESS, readResult.get(OUTCOME).asString(), "read-aliases should succeed: " + readResult);
        List<ModelNode> list = readResult.get(RESULT).asList();
        assertNotNull(list);
        assertTrue(list.stream().anyMatch(n -> alias1.equals(n.asString())), "Expected " + alias1);
        assertTrue(list.stream().anyMatch(n -> alias2.equals(n.asString())), "Expected " + alias2);

        for (String alias : new String[] { alias1, alias2 }) {
            ModelNode remove = Util.createOperation(OP_REMOVE_ALIAS, CREDENTIAL_STORE_ADDRESS);
            remove.get(ATTR_ALIAS).set(alias);
            ModelNode r = executeOperation(managementClient, remove);
            assertEquals(SUCCESS, r.get(OUTCOME).asString(), "remove-alias " + alias + " should succeed: " + r);
        }

        ModelNode afterRead = executeOperation(managementClient, readAliases);
        List<ModelNode> afterList = afterRead.get(RESULT).asList();
        assertFalse(afterList != null && afterList.stream().anyMatch(n -> alias1.equals(n.asString())),
                "Expected alias1 removed");
        assertFalse(afterList != null && afterList.stream().anyMatch(n -> alias2.equals(n.asString())),
                "Expected alias2 removed");
    }

    // =====================================================================
    // Expression resolution
    // =====================================================================

    /**
     * Stores a secret via add-alias, then resolves a {@code ${HC_VAULT::store:alias}} expression through
     * the WildFly management API {@code :resolve-expression} operation, verifying the expression resolver
     * returns the stored secret value.
     */
    @Test
    public void testExpressionResolutionReturnsStoredSecret(@ArquillianResource ManagementClient managementClient) throws IOException {
        String alias = "secret/crud.expression_test";
        String secretValue = "resolved-secret-42";

        ModelNode addAlias = Util.createOperation(OP_ADD_ALIAS, CREDENTIAL_STORE_ADDRESS);
        addAlias.get(ATTR_ALIAS).set(alias);
        addAlias.get(ATTR_SECRET_VALUE).set(secretValue);
        ModelNode addResult = executeOperation(managementClient, addAlias);
        assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

        try {
            String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":" + alias + "}";
            ModelNode resolveOp = Util.createOperation(OP_RESOLVE_EXPRESSION, PathAddress.EMPTY_ADDRESS);
            resolveOp.get("expression").set(expression);
            ModelNode resolveResult = executeOperation(managementClient, resolveOp);
            assertEquals(SUCCESS, resolveResult.get(OUTCOME).asString(),
                    "resolve-expression should succeed: " + resolveResult);
            assertEquals(secretValue, resolveResult.get(RESULT).asString(),
                    "Resolved expression should match the stored secret value");
        } finally {
            ModelNode removeAlias = Util.createOperation(OP_REMOVE_ALIAS, CREDENTIAL_STORE_ADDRESS);
            removeAlias.get(ATTR_ALIAS).set(alias);
            executeOperation(managementClient, removeAlias);
        }
    }

    // =====================================================================
    // Error paths
    // =====================================================================

    /**
     * Adding an alias that already exists in the credential store should fail with a message containing
     * "already exists".
     */
    @Test
    public void testAddDuplicateAliasFails(@ArquillianResource ManagementClient managementClient) throws IOException {
        String alias = "secret/crud.duplicate_test";

        ModelNode add1 = Util.createOperation(OP_ADD_ALIAS, CREDENTIAL_STORE_ADDRESS);
        add1.get(ATTR_ALIAS).set(alias);
        add1.get(ATTR_SECRET_VALUE).set("value1");
        ModelNode firstResult = executeOperation(managementClient, add1);
        assertEquals(SUCCESS, firstResult.get(OUTCOME).asString(), "First add should succeed: " + firstResult);

        try {
            ModelNode add2 = Util.createOperation(OP_ADD_ALIAS, CREDENTIAL_STORE_ADDRESS);
            add2.get(ATTR_ALIAS).set(alias);
            add2.get(ATTR_SECRET_VALUE).set("value2");
            ModelNode dupResult = executeOperation(managementClient, add2);
            assertEquals("failed", dupResult.get(OUTCOME).asString(),
                    "Duplicate add should fail: " + dupResult);
            assertTrue(dupResult.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                    "Should mention 'already exists': " + dupResult.get(FAILURE_DESCRIPTION).asString());
        } finally {
            ModelNode remove = Util.createOperation(OP_REMOVE_ALIAS, CREDENTIAL_STORE_ADDRESS);
            remove.get(ATTR_ALIAS).set(alias);
            executeOperation(managementClient, remove);
        }
    }

    /**
     * Removing an alias that does not exist in the credential store should fail with a message containing
     * "does not exist".
     */
    @Test
    public void testRemoveNonExistentAliasFails(@ArquillianResource ManagementClient managementClient) throws IOException {
        ModelNode removeAlias = Util.createOperation(OP_REMOVE_ALIAS, CREDENTIAL_STORE_ADDRESS);
        removeAlias.get(ATTR_ALIAS).set("secret/crud.no_such_key");
        ModelNode result = executeOperation(managementClient, removeAlias);
        assertEquals("failed", result.get(OUTCOME).asString(),
                "Remove of non-existent alias should fail: " + result);
        assertTrue(result.get(FAILURE_DESCRIPTION).asString().contains("does not exist"),
                "Should mention 'does not exist': " + result.get(FAILURE_DESCRIPTION).asString());
    }

    /**
     * Adding an alias without providing a secret-value should fail.
     */
    @Test
    public void testAddAliasWithoutSecretValueFails(@ArquillianResource ManagementClient managementClient) throws IOException {
        ModelNode addAlias = Util.createOperation(OP_ADD_ALIAS, CREDENTIAL_STORE_ADDRESS);
        addAlias.get(ATTR_ALIAS).set("secret/crud.no_secret");
        // Deliberately omit secret-value
        ModelNode result = executeOperation(managementClient, addAlias);
        assertEquals("failed", result.get(OUTCOME).asString(),
                "add-alias without secret-value should fail: " + result);
    }

    /**
     * Resolving an expression that references an alias not present in the credential store should fail.
     */
    @Test
    public void testExpressionResolutionFailsForMissingAlias(@ArquillianResource ManagementClient managementClient) throws IOException {
        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":secret/crud.nonexistent_key}";
        ModelNode resolveOp = Util.createOperation(OP_RESOLVE_EXPRESSION, PathAddress.EMPTY_ADDRESS);
        resolveOp.get("expression").set(expression);
        ModelNode result = executeOperation(managementClient, resolveOp);
        assertEquals("failed", result.get(OUTCOME).asString(),
                "resolve-expression for missing alias should fail: " + result);
        assertTrue(result.get(FAILURE_DESCRIPTION).asString().contains("not found"),
                "Should mention 'not found': " + result.get(FAILURE_DESCRIPTION).asString());
    }

    // =====================================================================
    // Credential store add / remove lifecycle
    // =====================================================================

    /**
     * Adds a second credential store at runtime, verifies it is functional by calling read-aliases, then removes it.
     */
    @Test
    public void testAddAndRemoveCredentialStoreAtRuntime(@ArquillianResource ManagementClient managementClient) throws IOException {
        String newStoreName = "vault-crud-second-store";
        PathAddress newStoreAddress = SUBSYSTEM_ADDRESS.append("credential-store", newStoreName);

        ModelNode add = Util.createAddOperation(newStoreAddress);
        add.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
        add.get("credential-reference", "clear-text").set(VAULT_TOKEN);
        ModelNode addResult = executeOperation(managementClient, add);
        assertEquals(SUCCESS, addResult.get(OUTCOME).asString(),
                "Add credential-store should succeed: " + addResult);

        ModelNode readAliases = Util.createOperation(OP_READ_ALIASES, newStoreAddress);
        ModelNode readResult = executeOperation(managementClient, readAliases);
        assertEquals(SUCCESS, readResult.get(OUTCOME).asString(),
                "read-aliases on new store should succeed: " + readResult);
        assertNotNull(readResult.get(RESULT).asList());

        ModelNode remove = Util.createRemoveOperation(newStoreAddress);
        remove.get("operation-headers", "allow-resource-service-restart").set(true);
        ModelNode removeResult = executeOperation(managementClient, remove);
        assertEquals(SUCCESS, removeResult.get(OUTCOME).asString(),
                "Remove credential-store should succeed: " + removeResult);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static ModelNode executeOperation(ManagementClient client, ModelNode operation) throws IOException {
        return client.getControllerClient().execute(operation);
    }

    // =====================================================================
    // Server setup — starts Vault container and adds credential-store
    // =====================================================================

    /**
     * Starts a HashiCorp Vault container and adds a credential-store resource to the running WildFly server
     * before tests execute, then removes the store and stops Vault after all tests complete.
     */
    public static final class VaultSetup implements ServerSetupTask {

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            vault = new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.21"))
                    .withVaultToken(VAULT_TOKEN)
                    .withInitCommand(
                            "secrets enable transit",
                            "write -f transit/keys/my-key",
                            "kv put secret/testing1 top_secret=password123"
                    );
            vault.start();

            ModelNode add = Util.createAddOperation(CREDENTIAL_STORE_ADDRESS);
            add.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
            add.get("credential-reference", "clear-text").set(VAULT_TOKEN);
            VaultHttpsElytronSetup.executeSuccess(managementClient, add);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            try {
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
