/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import org.testcontainers.containers.output.BaseConsumer;
import org.testcontainers.containers.output.OutputFrame;

/**
 * Prefixes Vault container log lines for easier correlation in test output.
 */
public class VaultContainerLogConsumer extends BaseConsumer<VaultContainerLogConsumer> {

    private final String prefix;

    public VaultContainerLogConsumer(String prefix) {
        this.prefix = prefix;
    }

    @Override
    public void accept(OutputFrame outputFrame) {
        if (outputFrame == null) {
            return;
        }
        String line = outputFrame.getUtf8StringWithoutLineEnding();
        if (line != null && !line.isEmpty()) {
            System.out.println("[" + prefix + "] " + line);
        }
    }
}
