/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.wildfly.extension.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.dmr.ModelNode;

/**
 * Add handler for the HashiCorp Vault subsystem.
 *
 */
public class VaultSubsystemAdd extends AbstractAddStepHandler {
    
    public static final VaultSubsystemAdd INSTANCE = new VaultSubsystemAdd();
    
    private VaultSubsystemAdd() {
        // Credential store capabilities are defined in CredentialStoreDefinition and VaultSubsystemDefinition
    }

    @Override
    protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
        ROOT_LOGGER.activatingHashiCorpVaultSubsystem();
    }
}