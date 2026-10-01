/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILURE_DESCRIPTION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.RunningMode;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Integration tests for new alias format features at DEFAULT stability level.
 *
 * Covers engine specification, custom mount points, multi-part secret paths,
 * nested key paths, and legacy format rejection.
 */
public class AliasFormatFeatureIntegrationTestCase extends SubsystemJUnit5TestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-format-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append("credential-store", CREDENTIAL_STORE_NAME);

    private static VaultContainer<?> vault;

    private KernelServices kernelServices;

    private static synchronized void ensureVaultStarted() {
        if (vault != null) {
            return;
        }
        vault = new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.21"))
                .withVaultToken(VAULT_TOKEN)
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "secrets enable -version=1 -path=secret-v1 kv",
                        "secrets enable -version=2 -path=custom kv",
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

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.DEFAULT) {
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
        return "<subsystem xmlns=\"urn:wildfly:hashicorp-vault:2.0\">\n"
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

    // =====================================================================
    // Engine specification
    // =====================================================================

    @Test
    public void testAddAliasWithExplicitKVv2Engine() throws Exception {
        String alias = "engine=KVv2#fmttest?engine_v2";
        try {
            ModelNode addResult = addAlias(alias, "engine-v2-value");
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

            ModelNode dupResult = addAlias(alias, "duplicate");
            assertEquals("failed", dupResult.get(OUTCOME).asString(), "Duplicate add should fail: " + dupResult);
            assertTrue(dupResult.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                    "Should mention 'already exists': " + dupResult.get(FAILURE_DESCRIPTION).asString());
        } finally {
            removeAlias(alias);
        }
    }

    @Test
    public void testAddAliasWithKVv1EngineAndMount() throws Exception {
        String alias = "engine=KVv1@secret-v1#fmttest?engine_v1";
        try {
            ModelNode addResult = addAlias(alias, "engine-v1-value");
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

            ModelNode dupResult = addAlias(alias, "duplicate");
            assertEquals("failed", dupResult.get(OUTCOME).asString(), "Duplicate add should fail: " + dupResult);
            assertTrue(dupResult.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                    "Should mention 'already exists': " + dupResult.get(FAILURE_DESCRIPTION).asString());
        } finally {
            removeAlias(alias);
        }
    }

    // =====================================================================
    // Custom mount point
    // =====================================================================

    @Test
    public void testAddAliasWithCustomMount() throws Exception {
        String alias = "@custom#fmttest?custom_mount";
        try {
            ModelNode addResult = addAlias(alias, "custom-mount-value");
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

            ModelNode dupResult = addAlias(alias, "duplicate");
            assertEquals("failed", dupResult.get(OUTCOME).asString(), "Duplicate add should fail: " + dupResult);
            assertTrue(dupResult.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                    "Should mention 'already exists': " + dupResult.get(FAILURE_DESCRIPTION).asString());
        } finally {
            removeAlias(alias);
        }
    }

    // =====================================================================
    // Combined engine + mount
    // =====================================================================

    @Test
    public void testAddAliasWithCombinedKVv2EngineAndCustomMount() throws Exception {
        String alias = "engine=KVv2@custom#fmttest?combined_v2";
        try {
            ModelNode addResult = addAlias(alias, "combined-v2-value");
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

            ModelNode dupResult = addAlias(alias, "duplicate");
            assertEquals("failed", dupResult.get(OUTCOME).asString(), "Duplicate add should fail: " + dupResult);
            assertTrue(dupResult.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                    "Should mention 'already exists': " + dupResult.get(FAILURE_DESCRIPTION).asString());
        } finally {
            removeAlias(alias);
        }
    }

    // =====================================================================
    // Multi-part secret paths
    // =====================================================================

    @Test
    public void testAddAliasWithMultiPartSecretPath() throws Exception {
        String alias = "#myapp/database?multipath_key";
        try {
            ModelNode addResult = addAlias(alias, "multipath-value");
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

            ModelNode dupResult = addAlias(alias, "duplicate");
            assertEquals("failed", dupResult.get(OUTCOME).asString(), "Duplicate add should fail: " + dupResult);
            assertTrue(dupResult.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                    "Should mention 'already exists': " + dupResult.get(FAILURE_DESCRIPTION).asString());
        } finally {
            removeAlias(alias);
        }
    }

    // =====================================================================
    // Nested key paths
    // =====================================================================

    @Test
    public void testAddAliasWithNestedKeyPath() throws Exception {
        String alias = "#fmttest?database/credentials/password";
        try {
            ModelNode addResult = addAlias(alias, "nested-password-value");
            assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

            ModelNode dupResult = addAlias(alias, "duplicate");
            assertEquals("failed", dupResult.get(OUTCOME).asString(), "Duplicate add should fail: " + dupResult);
            assertTrue(dupResult.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                    "Should mention 'already exists': " + dupResult.get(FAILURE_DESCRIPTION).asString());
        } finally {
            removeAlias(alias);
        }
    }

    // =====================================================================
    // Legacy format rejection at DEFAULT stability
    // =====================================================================

    @Test
    public void testLegacyDotFormatRejectedAtDefaultStability() throws Exception {
        ModelNode result = addAlias("testing1.top_secret", "should-not-matter");
        assertEquals("failed", result.get(OUTCOME).asString(),
                "Legacy dot format should be rejected at DEFAULT stability: " + result);
    }

    @Test
    public void testLegacySlashDotFormatRejectedAtDefaultStability() throws Exception {
        ModelNode result = addAlias("secret/testing1.top_secret", "should-not-matter");
        assertEquals("failed", result.get(OUTCOME).asString(),
                "Legacy slash-dot format should be rejected at DEFAULT stability: " + result);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private ModelNode addAlias(String alias, String secretValue) throws Exception {
        ModelNode op = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        op.get("alias").set(alias);
        op.get("secret-value").set(secretValue);
        return kernelServices.executeOperation(op);
    }

    private ModelNode removeAlias(String alias) throws Exception {
        ModelNode op = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
        op.get("alias").set(alias);
        return kernelServices.executeOperation(op);
    }
}
