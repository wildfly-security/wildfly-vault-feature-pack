/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.wildfly.extension.hashicorp.vault.VaultExtension.SUBSYSTEM_NAME;

import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;

import java.io.IOException;

/**
 * Base test case for the HashiCorp Vault subsystem.
 *
 */
public class SubsystemTestCase extends AbstractSubsystemBaseTest {

    public SubsystemTestCase() {
        super(SUBSYSTEM_NAME, new VaultExtension());
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("hashicorp-vault-community-1.0.xml");
    }

}
