/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.extension.hashicorp.vault.tests;

import org.testcontainers.vault.VaultContainer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HashiCorpVaultFeaturePackBasicTest {

    VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    @Test
    public void testBuild() {
        vaultTestContainer = startVaultTestContainer();
        // FIXME this test should run and fail
        assertEquals("test123", "test123");
    }

    public static VaultContainer<?> startVaultTestContainer() {
        VaultContainer<?> vaultTestContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();
        return vaultTestContainer;
    }

}
