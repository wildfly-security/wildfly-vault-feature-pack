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

        ModelNode addAlias = Util.createOperation("add-alias", VAULT_STORE_ADDRESS);
        addAlias.get(CredentialStoreDefinition.ALIAS.getName()).set(alias);
        addAlias.get(CredentialStoreDefinition.SECRET_VALUE.getName()).set(secretValue);
        ModelNode addResult = executeOperation(managementClient, addAlias);
        assertEquals(SUCCESS, addResult.get(OUTCOME).asString(),
                "add-alias should succeed with chained token: " + addResult);

        try {
            ModelNode readAliases = Util.createOperation("read-aliases", VAULT_STORE_ADDRESS);
            readAliases.get(CredentialStoreDefinition.PATH.getName()).set("");
            readAliases.get(CredentialStoreDefinition.RECURSIVE.getName()).set(true);
            ModelNode readResult = executeOperation(managementClient, readAliases);
            assertEquals(SUCCESS, readResult.get(OUTCOME).asString(),
                    "read-aliases should succeed: " + readResult);
            List<ModelNode> aliases = readResult.get(RESULT).asList();
            assertTrue(aliases.stream().anyMatch(n -> normalizedAlias.equals(n.asString())),
                    "Should contain the added alias '" + normalizedAlias + "': " + aliases);
        } finally {
            ModelNode removeAlias = Util.createOperation("remove-alias", VAULT_STORE_ADDRESS);
            removeAlias.get(CredentialStoreDefinition.ALIAS.getName()).set(alias);
            ModelNode removeResult = executeOperation(managementClient, removeAlias);
            assertEquals(SUCCESS, removeResult.get(OUTCOME).asString(),
                    "Cleanup of alias should succeed: " + removeResult);
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
        addAlias.get(CredentialStoreDefinition.ALIAS.getName()).set(alias);
        addAlias.get(CredentialStoreDefinition.SECRET_VALUE.getName()).set(secretValue);
        ModelNode addResult = executeOperation(managementClient, addAlias);
        assertEquals(SUCCESS, addResult.get(OUTCOME).asString(),
                "add-alias should succeed: " + addResult);

        ModelNode removeAlias = Util.createOperation("remove-alias", VAULT_STORE_ADDRESS);
        removeAlias.get(CredentialStoreDefinition.ALIAS.getName()).set(alias);
        ModelNode removeResult = executeOperation(managementClient, removeAlias);
        assertEquals(SUCCESS, removeResult.get(OUTCOME).asString(),
                "remove-alias should succeed with chained token: " + removeResult);
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
     * <p><b>Passes when:</b> {@code add-alias} fails with an authentication error,
     * proving the token from the Elytron store is actually used for Vault authentication.
     */
    @Test
    public void testWrongTokenValueCausesAuthFailure(@ArquillianResource ManagementClient managementClient) throws Exception {
        String wrongTokenAlias = "wrong-token";
        String badStoreName = "vault-wrong-token-store";
        PathAddress badStoreAddress = SUBSYSTEM_ADDRESS.append("credential-store", badStoreName);

        ModelNode storeWrongToken = Util.createOperation("add-alias", ELYTRON_CS_ADDRESS);
        storeWrongToken.get("alias").set(wrongTokenAlias);
        storeWrongToken.get("secret-value").set("bogus-not-a-real-token");
        ModelNode storeResult = executeOperation(managementClient, storeWrongToken);
        assertEquals(SUCCESS, storeResult.get(OUTCOME).asString(),
                "Storing wrong token in Elytron CS should succeed: " + storeResult);

        try {
            ModelNode addBadStore = Util.createAddOperation(badStoreAddress);
            addBadStore.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
            addBadStore.get("credential-reference", "store").set(ELYTRON_CS_NAME);
            addBadStore.get("credential-reference", "alias").set(wrongTokenAlias);
            ModelNode addResult = executeOperation(managementClient, addBadStore);
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(),
                    "Store creation should succeed (lazy initialization): " + addResult);

            ModelNode addAlias = Util.createOperation("add-alias", badStoreAddress);
            addAlias.get(CredentialStoreDefinition.ALIAS.getName()).set("should?fail");
            addAlias.get(CredentialStoreDefinition.SECRET_VALUE.getName()).set("irrelevant");
            ModelNode opResult = executeOperation(managementClient, addAlias);
            assertNotEquals(SUCCESS, opResult.get(OUTCOME).asString(),
                    "Operation with wrong token should fail: " + opResult);
        } finally {
            ModelNode removeBad = Util.createRemoveOperation(badStoreAddress);
            removeBad.get("operation-headers", "allow-resource-service-restart").set(true);
            ModelNode removeResult = executeOperation(managementClient, removeBad);
            assertEquals(SUCCESS, removeResult.get(OUTCOME).asString(),
                    "Cleanup of bad store should succeed: " + removeResult);

            ModelNode removeWrongToken = Util.createOperation("remove-alias", ELYTRON_CS_ADDRESS);
            removeWrongToken.get("alias").set(wrongTokenAlias);
            ModelNode removeTokenResult = executeOperation(managementClient, removeWrongToken);
            assertEquals(SUCCESS, removeTokenResult.get(OUTCOME).asString(),
                    "Cleanup of wrong token alias should succeed: " + removeTokenResult);
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

        try {
            ModelNode addSecret = Util.createOperation("add-alias", VAULT_STORE_ADDRESS);
            addSecret.get(CredentialStoreDefinition.ALIAS.getName()).set(ksPasswordAlias);
            addSecret.get(CredentialStoreDefinition.SECRET_VALUE.getName()).set(ksPassword);
            ModelNode secretResult = executeOperation(managementClient, addSecret);
            assertEquals(SUCCESS, secretResult.get(OUTCOME).asString(),
                    "Storing keystore password in Vault should succeed: " + secretResult);

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
        } finally {
            ModelNode removeKs = Util.createRemoveOperation(ksAddress);
            removeKs.get("operation-headers", "allow-resource-service-restart").set(true);
            ModelNode removeKsResult = executeOperation(managementClient, removeKs);
            assertEquals(SUCCESS, removeKsResult.get(OUTCOME).asString(),
                    "Cleanup of key-store should succeed: " + removeKsResult);

            ModelNode removeSecret = Util.createOperation("remove-alias", VAULT_STORE_ADDRESS);
            removeSecret.get(CredentialStoreDefinition.ALIAS.getName()).set(ksPasswordAlias);
            ModelNode removeSecretResult = executeOperation(managementClient, removeSecret);
            assertEquals(SUCCESS, removeSecretResult.get(OUTCOME).asString(),
                    "Cleanup of Vault alias should succeed: " + removeSecretResult);

            Files.deleteIfExists(ksFile);
        }
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static ModelNode executeOperation(ManagementClient client, ModelNode operation) throws IOException {
        return client.getControllerClient().execute(operation);
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

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            vault = new VaultContainer<>(DockerImageName.parse(VaultImages.VAULT))
                    .withVaultToken(VAULT_TOKEN);
            vault.start();

            Path jbossHome = Path.of(System.getProperty("jboss.home"));
            Path csFile = jbossHome.resolve("standalone/configuration/token-source.p12");
            Files.deleteIfExists(csFile);

            ModelNode addElytronCs = Util.createAddOperation(ELYTRON_CS_ADDRESS);
            addElytronCs.get("path").set("token-source.p12");
            addElytronCs.get("relative-to").set("jboss.server.config.dir");
            addElytronCs.get("create").set(true);
            addElytronCs.get("credential-reference", "clear-text").set(ELYTRON_CS_PASSWORD);
            VaultHttpsElytronSetup.executeSuccess(managementClient, addElytronCs);

            ModelNode storeToken = Util.createOperation("add-alias", ELYTRON_CS_ADDRESS);
            storeToken.get("alias").set(VAULT_TOKEN_ALIAS);
            storeToken.get("secret-value").set(VAULT_TOKEN);
            VaultHttpsElytronSetup.executeSuccess(managementClient, storeToken);

            ModelNode addVaultStore = Util.createAddOperation(VAULT_STORE_ADDRESS);
            addVaultStore.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
            addVaultStore.get("credential-reference", "store").set(ELYTRON_CS_NAME);
            addVaultStore.get("credential-reference", "alias").set(VAULT_TOKEN_ALIAS);
            VaultHttpsElytronSetup.executeSuccess(managementClient, addVaultStore);
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            try {
                ModelNode removeVault = Util.createRemoveOperation(VAULT_STORE_ADDRESS);
                removeVault.get("operation-headers", "allow-resource-service-restart").set(true);
                managementClient.getControllerClient().execute(removeVault);

                ModelNode removeElytronCs = Util.createRemoveOperation(ELYTRON_CS_ADDRESS);
                removeElytronCs.get("operation-headers", "allow-resource-service-restart").set(true);
                managementClient.getControllerClient().execute(removeElytronCs);
            } finally {
                if (vault != null) {
                    vault.stop();
                }
                Path jbossHome = Path.of(System.getProperty("jboss.home"));
                Files.deleteIfExists(jbossHome.resolve("standalone/configuration/token-source.p12"));
            }
        }
    }
}
