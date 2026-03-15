/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import java.io.IOException;

import org.junit.Test;

/**
 * Tests parsing and marshalling of the hashicorp-vault subsystem configuration
 */
public class CredentialStoreParsingTestCase extends SubsystemTestCase {

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("hashicorp-vault-community-1.0.xml");
    }

    @Test
    public void testParseAndMarshalModel_EmptySubsystem() throws Exception {
        standardSubsystemTest("hashicorp-vault-community-1.0.xml");
    }

    @Test
    public void testParseAndMarshalModel_CredentialStore_Full() throws Exception {
        standardSubsystemTest("hashicorp-vault-community-1.0-full.xml");
    }
}
