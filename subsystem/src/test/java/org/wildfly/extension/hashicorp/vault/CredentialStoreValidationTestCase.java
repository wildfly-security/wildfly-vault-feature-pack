/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.CHILDREN;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILURE_DESCRIPTION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OP_ADDR;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.READ_RESOURCE_DESCRIPTION_OPERATION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUBSYSTEM;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.client.helpers.ClientConstants;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for credential-store resource validation and management operations:
 * add with invalid model, remove non-existent, read-resource-description.
 */
public class CredentialStoreValidationTestCase extends SubsystemTestCase {

    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement(SUBSYSTEM, VaultExtension.SUBSYSTEM_NAME));
    private static final String CREDENTIAL_STORE = "credential-store";

    private KernelServices kernelServices;

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("hashicorp-vault-community-1.0.xml");
    }

    @Before
    public void bootKernel() throws Exception {
        kernelServices = createKernelServicesBuilder(createAdditionalInitialization())
                .setSubsystemXml(getSubsystemXml())
                .build();
        assertTrue("Subsystem boot failed: " + kernelServices.getBootError(), kernelServices.isSuccessfulBoot());
    }

    @Test
    public void testAddCredentialStoreMissingRequiredHostAddress() throws Exception {
        PathAddress storeAddress = SUBSYSTEM_ADDRESS.append(CREDENTIAL_STORE, "test-store");
        ModelNode add = Util.createAddOperation(storeAddress);
        add.get("credential-reference").setEmptyObject();

        ModelNode result = kernelServices.executeOperation(add);
        assertEquals("Expected add to fail", "failed", result.get(OUTCOME).asString());
        assertNotNull(result.get(FAILURE_DESCRIPTION));
        String desc = result.get(FAILURE_DESCRIPTION).asString();
        assertTrue("Failure should mention host-address or required attribute: " + desc,
                desc.contains("host-address") || desc.contains("WFLYCTL") || desc.contains("required"));
    }

    @Test
    public void testRemoveNonExistentCredentialStore() throws Exception {
        PathAddress storeAddress = SUBSYSTEM_ADDRESS.append(CREDENTIAL_STORE, "no-such-store");
        ModelNode remove = Util.createRemoveOperation(storeAddress);

        ModelNode result = kernelServices.executeOperation(remove);
        assertEquals("Expected remove to fail", "failed", result.get(OUTCOME).asString());
        assertNotNull(result.get(FAILURE_DESCRIPTION));
    }

    @Test
    public void testReadResourceDescriptionIncludesCredentialStore() throws Exception {
        ModelNode readDesc = new ModelNode();
        readDesc.get(OP).set(READ_RESOURCE_DESCRIPTION_OPERATION);
        readDesc.get(OP_ADDR).set(SUBSYSTEM_ADDRESS.toModelNode());
        readDesc.get("operations").set(true);
        readDesc.get("attributes").set(false);

        ModelNode result = kernelServices.executeOperation(readDesc);
        assertEquals("read-resource-description failed: " + result, SUCCESS, result.get(OUTCOME).asString());
        ModelNode desc = result.get(RESULT);
        assertNotNull(desc);
        assertTrue("Subsystem description should include credential-store child",
                desc.hasDefined(CHILDREN) && desc.get(CHILDREN).hasDefined(CREDENTIAL_STORE));
    }

    @Test
    public void testReadResourceEmptySubsystem() throws Exception {
        ModelNode read = Util.getReadResourceOperation(SUBSYSTEM_ADDRESS);
        ModelNode result = kernelServices.executeOperation(read);
        assertEquals("read-resource failed: " + result, SUCCESS, result.get(OUTCOME).asString());
        ModelNode subsystem = result.get(ClientConstants.RESULT);
        assertNotNull(subsystem);
        assertTrue("Expected no credential-store children", !subsystem.hasDefined(CREDENTIAL_STORE) || subsystem.get(CREDENTIAL_STORE).asList().isEmpty());
    }

    @Test
    public void testCredentialStoreResourceDescriptionHasExpectedAttributes() throws Exception {
        ModelNode readDesc = new ModelNode();
        readDesc.get(OP).set(READ_RESOURCE_DESCRIPTION_OPERATION);
        readDesc.get(OP_ADDR).set(SUBSYSTEM_ADDRESS.toModelNode());
        readDesc.get("recursive").set(true);
        readDesc.get("operations").set(false);
        readDesc.get("attributes").set(true);

        ModelNode result = kernelServices.executeOperation(readDesc);
        assertEquals("read-resource-description failed: " + result, SUCCESS, result.get(OUTCOME).asString());
        ModelNode desc = result.get(RESULT);
        assertNotNull(desc);
        ModelNode credentialStoreChild = desc.get(CHILDREN).get(CREDENTIAL_STORE);
        assertTrue("credential-store child type should be described", credentialStoreChild.isDefined());
        String descString = credentialStoreChild.toString();
        assertTrue("credential-store description should mention host-address: " + descString, descString.contains("host-address"));
        assertTrue("credential-store description should mention credential-reference: " + descString, descString.contains("credential-reference"));
    }
}
