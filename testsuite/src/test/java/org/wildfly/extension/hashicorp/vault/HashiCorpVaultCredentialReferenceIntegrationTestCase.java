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
import static org.wildfly.extension.hashicorp.vault.CredentialStoreDefinition.HOST_ADDRESS;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
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
 * Integration tests verifying that the hashicorp-vault credential store works as both a
 * credential-reference <b>consumer</b> (sourcing its Vault token from an Elytron credential
 * store) and a credential-reference <b>provider</b> (another subsystem sourcing a secret
 * from the vault store).
 * <p>
 * Existing tests only configure the Vault credential store with {@code clear-text} for the
 * token. This class proves that the {@code credential-reference} mechanism works end-to-end
 * in both directions: Elytron store &rarr; Vault token, and Vault store &rarr; Elytron key-store
 * password.
 */
@ExtendWith(ArquillianExtension.class)
@RunAsClient
@ServerSetup(HashiCorpVaultCredentialReferenceIntegrationTestCase.VaultSetup.class)
public class HashiCorpVaultCredentialReferenceIntegrationTestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String ELYTRON_CS_NAME = "token-source-store";
    private static final String ELYTRON_CS_PASSWORD = "changeit";
    private static final String VAULT_TOKEN_ALIAS = "vault-token";
    private static final String VAULT_STORE_NAME = "vault-chained-store";

    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress VAULT_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append(
            "credential-store", VAULT_STORE_NAME);
    private static final PathAddress ELYTRON_ADDRESS = PathAddress.pathAddress("subsystem", "elytron");
    private static final PathAddress ELYTRON_CS_ADDRESS = ELYTRON_ADDRESS.append(
            "credential-store", ELYTRON_CS_NAME);

    private static final String ATTR_ALIAS = CredentialStoreDefinition.ALIAS.getName();
    private static final String ATTR_SECRET_VALUE = CredentialStoreDefinition.SECRET_VALUE.getName();
    private static final String ATTR_PATH = CredentialStoreDefinition.PATH.getName();
    private static final String ATTR_RECURSIVE = CredentialStoreDefinition.RECURSIVE.getName();

    private static VaultContainer<?> vault;

    @Deployment
    public static JavaArchive deployment() {
        return ShrinkWrap.create(JavaArchive.class, "vault-credential-reference-test.jar");
    }

    // =====================================================================
    // Token chaining: Vault token sourced from Elytron credential store
    // =====================================================================

    /**
     * Verifies the Vault credential store initialized with its token sourced from an
     * Elytron credential store can perform add-alias and read-aliases operations.
     * <p><b>Passes when:</b> {@code add-alias} succeeds and {@code read-aliases} returns the
     * stored alias, proving the chained credential-reference resolved the Vault token.
     */
    @Test
    public void testCrudWithChainedToken(@ArquillianResource ManagementClient managementClient) throws Exception {
        String alias = "chained?crud_test";
        String normalizedAlias = "#" + alias;
        String secretValue = "chained-secret-value";

        boolean aliasAdded = false;
        Throwable testFailure = null;
        try {
            ModelNode addAlias = Util.createOperation("add-alias", VAULT_STORE_ADDRESS);
            addAlias.get(ATTR_ALIAS).set(alias);
            addAlias.get(ATTR_SECRET_VALUE).set(secretValue);
            ModelNode addResult = executeOperation(managementClient, addAlias);
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(),
                    "add-alias should succeed with chained token: " + addResult);
            aliasAdded = true;

            ModelNode readAliases = Util.createOperation("read-aliases", VAULT_STORE_ADDRESS);
            readAliases.get(ATTR_PATH).set("");
            readAliases.get(ATTR_RECURSIVE).set(true);
            ModelNode readResult = executeOperation(managementClient, readAliases);
            assertEquals(SUCCESS, readResult.get(OUTCOME).asString(),
                    "read-aliases should succeed: " + readResult);
            List<ModelNode> aliases = readResult.get(RESULT).asList();
            assertTrue(aliases.stream().anyMatch(n -> normalizedAlias.equals(n.asString())),
                    "Should contain the added alias '" + normalizedAlias + "': " + aliases);
        } catch (Throwable t) {
            testFailure = t;
            throw t;
        } finally {
            List<Exception> cleanupFailures = new ArrayList<>();
            if (aliasAdded) {
                collectCleanupFailure(managementClient,
                        removeAliasOp(VAULT_STORE_ADDRESS, alias),
                        "Cleanup of alias", cleanupFailures);
            }
            throwCleanupFailures(cleanupFailures, testFailure);
        }
    }

    /**
     * Verifies that remove-alias works when the Vault token is sourced from another
     * credential store.
     * <p><b>Passes when:</b> a secret stored via {@code add-alias} is successfully removed,
     * proving the entire chain (Elytron CS &rarr; Vault token &rarr; Vault operation) works.
     */
    @Test
    public void testRemoveAliasWithChainedToken(@ArquillianResource ManagementClient managementClient) throws Exception {
        String alias = "chained?remove_test";
        String secretValue = "remove-me";

        ModelNode addAlias = Util.createOperation("add-alias", VAULT_STORE_ADDRESS);
        addAlias.get(ATTR_ALIAS).set(alias);
        addAlias.get(ATTR_SECRET_VALUE).set(secretValue);
        assertOperationSuccess(managementClient, addAlias, "add-alias");

        ModelNode removeAlias = Util.createOperation("remove-alias", VAULT_STORE_ADDRESS);
        removeAlias.get(ATTR_ALIAS).set(alias);
        assertOperationSuccess(managementClient, removeAlias, "remove-alias with chained token");
    }

    /**
     * Verifies that the Vault credential store actually uses the token from the Elytron
     * credential store, not a fallback. A store configured with a nonexistent token alias
     * must fail at creation time because the credential-reference resolves to no credential.
     * <p><b>Passes when:</b> {@code credential-store:add} fails with {@code ELYHCVT0060},
     * proving the chained credential-reference is the actual authentication path.
     */
    @Test
    public void testNonexistentTokenAliasCausesCreationFailure(@ArquillianResource ManagementClient managementClient) throws Exception {
        String badStoreName = "vault-bad-token-store";
        PathAddress badStoreAddress = SUBSYSTEM_ADDRESS.append("credential-store", badStoreName);

        ModelNode addBadStore = Util.createAddOperation(badStoreAddress);
        addBadStore.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
        addBadStore.get("credential-reference", "store").set(ELYTRON_CS_NAME);
        addBadStore.get("credential-reference", "alias").set("nonexistent-alias");
        ModelNode addResult = executeOperation(managementClient, addBadStore);

        assertNotEquals(SUCCESS, addResult.get(OUTCOME).asString(),
                "Store creation with nonexistent token alias should fail: " + addResult);
        assertTrue(addResult.get(FAILURE_DESCRIPTION).asString().contains("ELYHCVT0060"),
                "Failure should indicate no authentication method configured: "
                + addResult.get(FAILURE_DESCRIPTION));
    }

    /**
     * Verifies that the Vault credential store fails when the Elytron credential store
     * contains a wrong token value. The store starts successfully (the token resolves) but
     * the first Vault operation fails because Vault rejects the invalid token.
     * <p><b>Passes when:</b> {@code add-alias} fails with {@code ELYHCVT0034}
     * (all login strategies failed), proving the token from the Elytron store is actually
     * used for Vault authentication and that the rejection is an auth failure, not an
     * unrelated error.
     */
    @Test
    public void testWrongTokenValueCausesAuthFailure(@ArquillianResource ManagementClient managementClient) throws Exception {
        String wrongTokenAlias = "wrong-token";
        String badStoreName = "vault-wrong-token-store";
        PathAddress badStoreAddress = SUBSYSTEM_ADDRESS.append("credential-store", badStoreName);

        boolean wrongTokenStored = false;
        boolean storeCreated = false;
        Throwable testFailure = null;
        try {
            ModelNode storeWrongToken = Util.createOperation("add-alias", ELYTRON_CS_ADDRESS);
            storeWrongToken.get("alias").set(wrongTokenAlias);
            storeWrongToken.get("secret-value").set("bogus-not-a-real-token");
            ModelNode storeResult = executeOperation(managementClient, storeWrongToken);
            assertEquals(SUCCESS, storeResult.get(OUTCOME).asString(),
                    "Storing wrong token in Elytron CS should succeed: " + storeResult);
            wrongTokenStored = true;

            ModelNode addBadStore = Util.createAddOperation(badStoreAddress);
            addBadStore.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
            addBadStore.get("credential-reference", "store").set(ELYTRON_CS_NAME);
            addBadStore.get("credential-reference", "alias").set(wrongTokenAlias);
            ModelNode addResult = executeOperation(managementClient, addBadStore);
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(),
                    "Store creation should succeed (lazy initialization): " + addResult);
            storeCreated = true;

            ModelNode addAlias = Util.createOperation("add-alias", badStoreAddress);
            addAlias.get(ATTR_ALIAS).set("should?fail");
            addAlias.get(ATTR_SECRET_VALUE).set("irrelevant");
            ModelNode opResult = executeOperation(managementClient, addAlias);
            assertNotEquals(SUCCESS, opResult.get(OUTCOME).asString(),
                    "Operation with wrong token should fail: " + opResult);
            assertTrue(opResult.get(FAILURE_DESCRIPTION).asString().contains("ELYHCVT0034"),
                    "Failure should indicate authentication rejection (all login strategies failed): "
                    + opResult.get(FAILURE_DESCRIPTION));
        } catch (Throwable t) {
            testFailure = t;
            throw t;
        } finally {
            List<Exception> cleanupFailures = new ArrayList<>();

            if (storeCreated) {
                ModelNode removeBad = Util.createRemoveOperation(badStoreAddress);
                removeBad.get("operation-headers", "allow-resource-service-restart").set(true);
                collectCleanupFailure(managementClient, removeBad,
                        "Cleanup of bad store", cleanupFailures);
            }

            if (wrongTokenStored) {
                collectCleanupFailure(managementClient,
                        removeAliasOp(ELYTRON_CS_ADDRESS, wrongTokenAlias),
                        "Cleanup of wrong token alias", cleanupFailures);
            }

            throwCleanupFailures(cleanupFailures, testFailure);
        }
    }

    // =====================================================================
    // Vault store as credential-reference provider for Elytron key-store
    // =====================================================================

    /**
     * Stores a keystore password in the Vault credential store, then creates an Elytron
     * key-store resource that retrieves its password from the Vault store via
     * {@code credential-reference={store=vault-chained-store, alias=...}}.
     * <p><b>Passes when:</b> the Elytron key-store resource is added successfully, proving
     * that another subsystem can use the Vault credential store as a credential-reference source.
     */
    @Test
    public void testVaultStoreAsCredentialReferenceSource(@ArquillianResource ManagementClient managementClient) throws Exception {
        String ksPasswordAlias = "credref?ks_password";
        String ksPassword = "keystorepass123";
        String ksName = "vault-backed-ks";
        PathAddress ksAddress = ELYTRON_ADDRESS.append("key-store", ksName);

        Path jbossHome = Path.of(System.getProperty("jboss.home"));
        Path ksFile = jbossHome.resolve("standalone/configuration/vault-backed-test.p12");

        boolean secretStored = false;
        boolean ksCreated = false;
        Throwable testFailure = null;
        try {
            ModelNode addSecret = Util.createOperation("add-alias", VAULT_STORE_ADDRESS);
            addSecret.get(ATTR_ALIAS).set(ksPasswordAlias);
            addSecret.get(ATTR_SECRET_VALUE).set(ksPassword);
            ModelNode secretResult = executeOperation(managementClient, addSecret);
            assertEquals(SUCCESS, secretResult.get(OUTCOME).asString(),
                    "Storing keystore password in Vault should succeed: " + secretResult);
            secretStored = true;

            createEmptyPkcs12(ksFile, ksPassword.toCharArray());

            ModelNode addKs = Util.createAddOperation(ksAddress);
            addKs.get("type").set("PKCS12");
            addKs.get("path").set("vault-backed-test.p12");
            addKs.get("relative-to").set("jboss.server.config.dir");
            addKs.get("credential-reference", "store").set(VAULT_STORE_NAME);
            addKs.get("credential-reference", "alias").set(ksPasswordAlias);
            ModelNode ksResult = executeOperation(managementClient, addKs);
            assertEquals(SUCCESS, ksResult.get(OUTCOME).asString(),
                    "Elytron key-store with Vault-sourced password should load: " + ksResult
                    + (ksResult.hasDefined(FAILURE_DESCRIPTION) ? " / " + ksResult.get(FAILURE_DESCRIPTION) : ""));
            ksCreated = true;
        } catch (Throwable t) {
            testFailure = t;
            throw t;
        } finally {
            List<Exception> cleanupFailures = new ArrayList<>();

            if (ksCreated) {
                ModelNode removeKs = Util.createRemoveOperation(ksAddress);
                removeKs.get("operation-headers", "allow-resource-service-restart").set(true);
                collectCleanupFailure(managementClient, removeKs,
                        "Cleanup of key-store", cleanupFailures);
            }

            if (secretStored) {
                collectCleanupFailure(managementClient,
                        removeAliasOp(VAULT_STORE_ADDRESS, ksPasswordAlias),
                        "Cleanup of Vault alias", cleanupFailures);
            }

            try {
                Files.deleteIfExists(ksFile);
            } catch (IOException e) {
                cleanupFailures.add(new RuntimeException("Cleanup of keystore file", e));
            }

            throwCleanupFailures(cleanupFailures, testFailure);
        }
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static ModelNode executeOperation(ManagementClient client, ModelNode operation) throws IOException {
        return client.getControllerClient().execute(operation);
    }

    private static void assertOperationSuccess(ManagementClient client, ModelNode operation,
                                               String description) throws IOException {
        ModelNode result = executeOperation(client, operation);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(),
                description + " should succeed: " + result);
    }

    private static void collectCleanupFailure(ManagementClient client, ModelNode operation,
                                              String description, List<Exception> failures) {
        try {
            ModelNode result = executeOperation(client, operation);
            if (!SUCCESS.equals(result.get(OUTCOME).asString())) {
                failures.add(new RuntimeException(description + " failed: " + result));
            }
        } catch (Exception e) {
            failures.add(new RuntimeException(description, e));
        }
    }

    private static ModelNode removeAliasOp(PathAddress storeAddress, String alias) {
        ModelNode op = Util.createOperation("remove-alias", storeAddress);
        op.get(ATTR_ALIAS).set(alias);
        return op;
    }

    private static void throwCleanupFailures(List<Exception> failures,
                                             Throwable originalFailure) {
        if (!failures.isEmpty()) {
            AssertionError cleanupError = new AssertionError("Cleanup failed");
            for (Exception failure : failures) {
                cleanupError.addSuppressed(failure);
            }
            if (originalFailure != null) {
                originalFailure.addSuppressed(cleanupError);
            } else {
                throw cleanupError;
            }
        }
    }

    private static void createEmptyPkcs12(Path path, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);
        Files.createDirectories(path.getParent());
        try (OutputStream os = Files.newOutputStream(path)) {
            ks.store(os, password);
        }
    }

    // =====================================================================
    // Server setup
    // =====================================================================

    /**
     * Creates an Elytron credential store with the Vault token, then adds a hashicorp-vault
     * credential store that obtains its token from the Elytron store via
     * {@code credential-reference={store=token-source-store, alias=vault-token}}.
     */
    public static final class VaultSetup implements ServerSetupTask {

        private static boolean elytronCsCreated;
        private static boolean vaultStoreCreated;
        private Path csFile;

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            elytronCsCreated = false;
            vaultStoreCreated = false;

            VaultTestSupport.assumeDockerAvailable();
            vault = new VaultContainer<>(DockerImageName.parse(VaultImages.VAULT))
                    .withVaultToken(VAULT_TOKEN);
            vault.start();

            Path jbossHome = Path.of(System.getProperty("jboss.home"));
            csFile = jbossHome.resolve("standalone/configuration/token-source.p12");
            Files.deleteIfExists(csFile);

            ModelNode addElytronCs = Util.createAddOperation(ELYTRON_CS_ADDRESS);
            addElytronCs.get("path").set("token-source.p12");
            addElytronCs.get("relative-to").set("jboss.server.config.dir");
            addElytronCs.get("create").set(true);
            addElytronCs.get("credential-reference", "clear-text").set(ELYTRON_CS_PASSWORD);
            VaultHttpsElytronSetup.executeSuccess(managementClient, addElytronCs);
            elytronCsCreated = true;

            ModelNode storeToken = Util.createOperation("add-alias", ELYTRON_CS_ADDRESS);
            storeToken.get("alias").set(VAULT_TOKEN_ALIAS);
            storeToken.get("secret-value").set(VAULT_TOKEN);
            VaultHttpsElytronSetup.executeSuccess(managementClient, storeToken);

            ModelNode addVaultStore = Util.createAddOperation(VAULT_STORE_ADDRESS);
            addVaultStore.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
            addVaultStore.get("credential-reference", "store").set(ELYTRON_CS_NAME);
            addVaultStore.get("credential-reference", "alias").set(VAULT_TOKEN_ALIAS);
            VaultHttpsElytronSetup.executeSuccess(managementClient, addVaultStore);
            vaultStoreCreated = true;
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            List<Exception> cleanupFailures = new ArrayList<>();

            if (vaultStoreCreated) {
                ModelNode removeVault = Util.createRemoveOperation(VAULT_STORE_ADDRESS);
                removeVault.get("operation-headers", "allow-resource-service-restart").set(true);
                collectCleanupFailure(managementClient, removeVault,
                        "tearDown: remove vault store", cleanupFailures);
            }

            if (elytronCsCreated) {
                ModelNode removeElytronCs = Util.createRemoveOperation(ELYTRON_CS_ADDRESS);
                removeElytronCs.get("operation-headers", "allow-resource-service-restart").set(true);
                collectCleanupFailure(managementClient, removeElytronCs,
                        "tearDown: remove elytron credential-store", cleanupFailures);
            }

            if (vault != null) {
                try {
                    vault.stop();
                    vault = null;
                } catch (Exception e) {
                    cleanupFailures.add(new RuntimeException("tearDown: stop vault container", e));
                }
            }

            try {
                if (csFile != null) {
                    Files.deleteIfExists(csFile);
                    csFile = null;
                }
            } catch (IOException e) {
                cleanupFailures.add(new RuntimeException("tearDown: delete token-source.p12", e));
            }

            throwCleanupFailures(cleanupFailures, null);
        }
    }
}
