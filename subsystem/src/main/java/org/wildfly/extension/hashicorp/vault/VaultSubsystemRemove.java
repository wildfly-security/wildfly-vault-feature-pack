/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import org.jboss.as.controller.AbstractRemoveStepHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.dmr.ModelNode;

/**
 * Remove handler for the HashiCorp Vault subsystem.
 */
public class VaultSubsystemRemove extends AbstractRemoveStepHandler {

    public static final VaultSubsystemRemove INSTANCE = new VaultSubsystemRemove();

    @Override
    protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model)
            throws OperationFailedException {
        // Runtime cleanup is handled by individual connection removals
    }
}