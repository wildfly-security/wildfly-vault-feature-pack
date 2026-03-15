/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Credential store integration tests
 */
public class CredentialStoreVaultIntegrationTestCase extends SubsystemTestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append("credential-store", CREDENTIAL_STORE_NAME);

    private static VaultContainer<?> vault;

    private KernelServices kernelServices;

    @BeforeClass
    public static void startVault() {
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

    @AfterClass
    public static void stopVault() {
        if (vault != null) {
            vault.stop();
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
        String hostAddress = vault.getHttpHostAddress();
        return "<subsystem xmlns=\"urn:wildfly:hashicorp-vault:community:1.0\">\n"
                + "    <credential-store name=\"" + CREDENTIAL_STORE_NAME + "\" host-address=\"" + hostAddress + "\">\n"
                + "        <credential-reference clear-text=\"" + VAULT_TOKEN + "\"/>\n"
                + "    </credential-store>\n"
                + "</subsystem>";
    }

    @Before
    public void bootKernel() throws Exception {
        kernelServices = createKernelServicesBuilder(createAdditionalInitialization())
                .setSubsystemXml(getSubsystemXml())
                .build();
        assertTrue("Subsystem boot failed: " + kernelServices.getBootError(), kernelServices.isSuccessfulBoot());
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
        assertEquals("Add credential-store should succeed: " + result, SUCCESS, result.get(OUTCOME).asString());

        kernelServices.getContainer().awaitStability();

        ModelNode readAliases = Util.createOperation("read-aliases", newStoreAddress);
        ModelNode readResult = kernelServices.executeOperation(readAliases);
        assertEquals("read-aliases on added store should succeed: " + readResult, SUCCESS, readResult.get(OUTCOME).asString());
        assertNotNull(readResult.get(RESULT).asList());

        ModelNode remove = Util.createRemoveOperation(newStoreAddress);
        ModelNode removeResult = kernelServices.executeOperation(remove);
        assertEquals("Remove added credential-store should succeed: " + removeResult, SUCCESS, removeResult.get(OUTCOME).asString());
    }

    @Test
    public void testReadAliasesSucceeds() throws Exception {
        ModelNode op = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        ModelNode result = kernelServices.executeOperation(op);
        assertEquals("read-aliases should succeed: " + result, SUCCESS, result.get(OUTCOME).asString());
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
        assertEquals("add-alias should succeed: " + addResult, SUCCESS, addResult.get(OUTCOME).asString());

        ModelNode readAliases = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        readAliases.get("path").set("secret");
        readAliases.get("recursive").set(true);
        ModelNode readResult = kernelServices.executeOperation(readAliases);
        assertEquals("read-aliases should succeed: " + readResult, SUCCESS, readResult.get(OUTCOME).asString());
        List<ModelNode> aliasList = readResult.get(RESULT).asList();
        assertNotNull(aliasList);
        assertTrue("Expected alias " + alias + " in " + aliasList, aliasList.stream().anyMatch(n -> alias.equals(n.asString())));

        ModelNode removeAlias = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
        removeAlias.get("alias").set(alias);
        ModelNode removeResult = kernelServices.executeOperation(removeAlias);
        assertEquals("remove-alias should succeed: " + removeResult, SUCCESS, removeResult.get(OUTCOME).asString());

        ModelNode readAfter = kernelServices.executeOperation(readAliases);
        assertEquals("read-aliases after remove should succeed: " + readAfter, SUCCESS, readAfter.get(OUTCOME).asString());
        List<ModelNode> afterList = readAfter.get(RESULT).asList();
        assertFalse("Expected alias to be removed", afterList != null && afterList.stream().anyMatch(n -> alias.equals(n.asString())));
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
            assertEquals("add-alias " + alias + " should succeed: " + r, SUCCESS, r.get(OUTCOME).asString());
        }

        ModelNode readResult = kernelServices.executeOperation(readAliases);
        assertEquals("read-aliases should succeed: " + readResult, SUCCESS, readResult.get(OUTCOME).asString());
        List<ModelNode> list = readResult.get(RESULT).asList();
        assertNotNull(list);
        assertTrue("Expected " + alias1, list.stream().anyMatch(n -> alias1.equals(n.asString())));
        assertTrue("Expected " + alias2, list.stream().anyMatch(n -> alias2.equals(n.asString())));

        for (String alias : new String[] { alias1, alias2 }) {
            ModelNode remove = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
            remove.get("alias").set(alias);
            ModelNode r = kernelServices.executeOperation(remove);
            assertEquals("remove-alias " + alias + " should succeed: " + r, SUCCESS, r.get(OUTCOME).asString());
        }

        List<ModelNode> afterList = kernelServices.executeOperation(readAliases).get(RESULT).asList();
        assertFalse("Expected alias1 removed", afterList != null && afterList.stream().anyMatch(n -> alias1.equals(n.asString())));
        assertFalse("Expected alias2 removed", afterList != null && afterList.stream().anyMatch(n -> alias2.equals(n.asString())));
    }
}
