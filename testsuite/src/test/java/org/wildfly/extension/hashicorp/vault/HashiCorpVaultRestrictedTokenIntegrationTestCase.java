/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILURE_DESCRIPTION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.INCLUDE_DEFAULTS;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.READ_RESOURCE_OPERATION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.extension.hashicorp.vault.CredentialStoreDefinition.HOST_ADDRESS;

import java.io.IOException;

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
import org.testcontainers.containers.Container;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Integration test verifying that management operations on a credential store backed by a
 * restricted-policy Vault token produce clear error messages without leaking the token or
 * secret values, and that {@code read-resource} does not expose the token.
 * <p>
 * The Vault policy grants read-only access to {@code secret/data/allowed} only. All write,
 * delete, and list operations are denied, as is access to any other path.
 */
@ExtendWith(ArquillianExtension.class)
@RunAsClient
@ServerSetup(HashiCorpVaultRestrictedTokenIntegrationTestCase.VaultSetup.class)
public class HashiCorpVaultRestrictedTokenIntegrationTestCase {

    private static final String ROOT_TOKEN = "myroot";
    private static final String RESTRICTED_TOKEN = "restricted-token";
    private static final String SECRET_VALUE = "s3cr3t-value";
    private static final String CREDENTIAL_STORE_NAME = "vault-restricted-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append(
            "credential-store", CREDENTIAL_STORE_NAME);

    private static final String ATTR_ALIAS = CredentialStoreDefinition.ALIAS.getName();
    private static final String ATTR_SECRET_VALUE = CredentialStoreDefinition.SECRET_VALUE.getName();

    private static VaultContainer<?> vault;

    @Deployment
    public static JavaArchive deployment() {
        return ShrinkWrap.create(JavaArchive.class, "vault-restricted-token-test.jar");
    }

    // =====================================================================
    // Sanity check — restricted token works for allowed operations
    // =====================================================================

    /**
     * Reads aliases from the path the restricted token has read access to.
     * <p><b>Passes when:</b> {@code read-aliases} on {@code #allowed} succeeds and returns
     * the seeded key {@code my_key}. This proves the Vault policy and token are correctly
     * configured — without this, all forbidden tests could pass vacuously if the token
     * were completely broken.
     */
    @Test
    public void testReadAliasesAllowedPathSucceeds(@ArquillianResource ManagementClient managementClient) throws Exception {
        ModelNode op = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        op.get(CredentialStoreDefinition.PATH.getName()).set("#allowed");

        ModelNode result = executeOperation(managementClient, op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(),
                "read-aliases on allowed path should succeed: " + result);
        String aliases = result.get(RESULT).toString();
        assertTrue(aliases.contains("my_key"),
                "Result should contain the seeded key 'my_key': " + aliases);
    }

    // =====================================================================
    // Authorization failure tests
    // =====================================================================

    /**
     * Attempts to store a secret using a token that has no write capability.
     * <p><b>Passes when:</b> {@code add-alias} fails with {@code outcome=failed}, the failure
     * description contains {@code WFLYHCVT0017} (unable to add alias) and {@code Forbidden},
     * mentions the denied path, and does not contain the restricted token value or the secret
     * value being stored.
     */
    @Test
    public void testAddAliasForbidden(@ArquillianResource ManagementClient managementClient) throws Exception {
        ModelNode op = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        op.get(ATTR_ALIAS).set("#forbidden-path?write_test");
        op.get(ATTR_SECRET_VALUE).set(SECRET_VALUE);

        ModelNode result = executeOperation(managementClient, op);
        assertOperationForbidden(result, "add-alias", "WFLYHCVT0017", "forbidden-path");
    }

    /**
     * Attempts to remove a secret using a token that has no delete capability.
     * <p><b>Passes when:</b> {@code remove-alias} fails with {@code outcome=failed}, the failure
     * description contains {@code WFLYHCVT0019} (unable to remove alias) and {@code 403},
     * and does not contain the restricted token value.
     */
    @Test
    public void testRemoveAliasForbidden(@ArquillianResource ManagementClient managementClient) throws Exception {
        ModelNode op = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
        op.get(ATTR_ALIAS).set("#allowed?my_key");

        ModelNode result = executeOperation(managementClient, op);
        assertOperationForbidden(result, "remove-alias", "WFLYHCVT0019", "403");
    }

    /**
     * Attempts to list aliases on a path the restricted token cannot list.
     * <p><b>Passes when:</b> {@code read-aliases} fails with {@code outcome=failed}, the failure
     * description contains {@code WFLYHCVT0013} (unable to read aliases) and {@code Forbidden},
     * mentions the denied path, and does not contain the restricted token value.
     */
    @Test
    public void testReadAliasesForbiddenPath(@ArquillianResource ManagementClient managementClient) throws Exception {
        ModelNode op = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        op.get(CredentialStoreDefinition.PATH.getName()).set("#denied-path");
        op.get(CredentialStoreDefinition.RECURSIVE.getName()).set(true);

        ModelNode result = executeOperation(managementClient, op);
        assertOperationForbidden(result, "read-aliases", "WFLYHCVT0013", "denied-path");
    }

    // =====================================================================
    // Token exposure tests
    // =====================================================================

    /**
     * Reads the credential store resource and verifies the Vault token only appears inside the
     * {@code credential-reference} attribute and nowhere else (e.g. {@code host-address}).
     * <p><b>Passes when:</b> {@code read-resource(include-defaults=true)} succeeds, the token
     * appears only in {@code credential-reference.clear-text}, and the root token is not present.
     */
    @Test
    public void testReadResourceTokenOnlyInCredentialReference(@ArquillianResource ManagementClient managementClient) throws Exception {
        ModelNode op = Util.createOperation(READ_RESOURCE_OPERATION, CREDENTIAL_STORE_ADDRESS);
        op.get(INCLUDE_DEFAULTS).set(true);

        ModelNode result = executeOperation(managementClient, op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(),
                "read-resource should succeed: " + result);

        ModelNode resource = result.get(RESULT);
        assertEquals(RESTRICTED_TOKEN,
                resource.get("credential-reference", "clear-text").asString(),
                "credential-reference should contain the configured token");

        // Verify the token does not leak into other attributes
        String hostAddress = resource.get("host-address").asString();
        assertFalse(hostAddress.contains(RESTRICTED_TOKEN),
                "host-address must not contain the token: " + hostAddress);

        // Verify root token is never exposed
        String fullResult = result.toString();
        assertFalse(fullResult.contains(ROOT_TOKEN),
                "read-resource must not expose the root token: " + fullResult);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static ModelNode executeOperation(ManagementClient client, ModelNode operation) throws IOException {
        return client.getControllerClient().execute(operation);
    }

    private static void assertOperationForbidden(ModelNode result, String operationName,
            String expectedErrorCode, String expectedSubstring) {
        assertEquals("failed", result.get(OUTCOME).asString(),
                operationName + " should fail with a restricted token: " + result);

        String failureDescription = result.get(FAILURE_DESCRIPTION).asString();

        assertTrue(failureDescription.contains(expectedErrorCode),
                operationName + " failure should contain error code " + expectedErrorCode + ": " + failureDescription);
        assertTrue(failureDescription.contains("Forbidden") || failureDescription.contains("403"),
                operationName + " failure should indicate authorization denial (Forbidden/403): " + failureDescription);
        assertTrue(failureDescription.contains(expectedSubstring),
                operationName + " failure should mention '" + expectedSubstring + "': " + failureDescription);

        assertFalse(failureDescription.contains(RESTRICTED_TOKEN),
                operationName + " failure must not leak the restricted token: " + failureDescription);
        assertFalse(failureDescription.contains(ROOT_TOKEN),
                operationName + " failure must not leak the root token: " + failureDescription);
        assertFalse(failureDescription.contains(SECRET_VALUE),
                operationName + " failure must not leak the secret value: " + failureDescription);
    }

    // =====================================================================
    // Server setup
    // =====================================================================

    /**
     * Starts a HashiCorp Vault container, seeds a test secret, creates a restricted ACL policy
     * (read-only on {@code secret/data/allowed}), generates a token with that policy, and adds
     * a credential store to the WildFly server using the restricted token.
     */
    public static final class VaultSetup implements ServerSetupTask {

        private boolean credentialStoreCreated;

        @Override
        public void setup(ManagementClient managementClient, String containerId) throws Exception {
            VaultTestSupport.assumeDockerAvailable();
            vault = new VaultContainer<>(DockerImageName.parse(VaultImages.VAULT))
                    .withVaultToken(ROOT_TOKEN)
                    .withInitCommand(
                            "kv put secret/allowed my_key=my_value"
                    );
            vault.start();

            Container.ExecResult policyResult = vault.execInContainer("sh", "-c",
                    "echo 'path \"secret/data/allowed\" { capabilities = [\"read\"] }' "
                    + "| vault policy write restricted -");
            if (policyResult.getExitCode() != 0) {
                throw new RuntimeException("Failed to create Vault policy: " + policyResult.getStderr());
            }

            Container.ExecResult tokenResult = vault.execInContainer("vault", "token", "create",
                    "-policy=restricted", "-id=" + RESTRICTED_TOKEN, "-ttl=1h");
            if (tokenResult.getExitCode() != 0) {
                throw new RuntimeException("Failed to create restricted token: " + tokenResult.getStderr());
            }

            ModelNode add = Util.createAddOperation(CREDENTIAL_STORE_ADDRESS);
            add.get(HOST_ADDRESS).set(vault.getHttpHostAddress());
            add.get("credential-reference", "clear-text").set(RESTRICTED_TOKEN);
            VaultHttpsElytronSetup.executeSuccess(managementClient, add);
            credentialStoreCreated = true;
        }

        @Override
        public void tearDown(ManagementClient managementClient, String containerId) throws Exception {
            try {
                if (credentialStoreCreated) {
                    ModelNode remove = Util.createRemoveOperation(CREDENTIAL_STORE_ADDRESS);
                    remove.get("operation-headers", "allow-resource-service-restart").set(true);
                    managementClient.getControllerClient().execute(remove);
                    credentialStoreCreated = false;
                }
            } finally {
                if (vault != null) {
                    vault.stop();
                    vault = null;
                }
            }
        }
    }
}
