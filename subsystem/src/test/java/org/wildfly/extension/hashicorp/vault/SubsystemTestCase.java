/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.wildfly.extension.hashicorp.vault.VaultExtension.SUBSYSTEM_NAME;

import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.version.Stability;

import java.io.IOException;

/**
 * Base test case for the HashiCorp Vault subsystem.
 *
 */
public class SubsystemTestCase extends AbstractSubsystemBaseTest {

    public SubsystemTestCase() {
        super(SUBSYSTEM_NAME, new VaultExtension(), Stability.EXPERIMENTAL);
    }

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.EXPERIMENTAL);
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("hashicorp-vault-experimental-1.0.xml");
    }

    @Override
    protected String getSubsystemXsdPath() throws Exception {
        return "schema/wildfly-hashicorp-vault_experimental_1_0.xsd";
    }

}
