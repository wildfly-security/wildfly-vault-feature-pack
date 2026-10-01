/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import java.io.IOException;

import javax.xml.stream.XMLStreamException;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests parsing and marshalling of the hashicorp-vault subsystem configuration
 */
public class CredentialStoreParsingTestCase extends SubsystemTestCase {

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("hashicorp-vault-2.0.xml");
    }

    @Test
    public void testParseAndMarshalModel_EmptySubsystem() throws Exception {
        standardSubsystemTest("hashicorp-vault-2.0.xml");
    }

    @Test
    public void testParseAndMarshalModel_CredentialStore_Full() throws Exception {
        standardSubsystemTest("hashicorp-vault-2.0-full.xml");
    }

    @Test
    public void testLegacyAuthenticationContextAttributeRejected() throws IOException {
        String xml = readResource("hashicorp-vault-1.0-authentication-context.xml");
        try {
            parse(xml);
            Assert.fail("Expected XMLStreamException for authentication-context attribute in legacy schema");
        } catch (XMLStreamException e) {
            Assert.assertTrue("Exception message should mention authentication-context: " + e.getMessage(),
                    e.getMessage().contains("authentication-context"));
            Assert.assertTrue("Exception message should mention client-ssl-context: " + e.getMessage(),
                    e.getMessage().contains("client-ssl-context"));
        }
    }
}
