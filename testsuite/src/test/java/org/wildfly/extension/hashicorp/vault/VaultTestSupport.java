/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.testcontainers.DockerClientFactory;

/** Shared prerequisites for tests that use a Vault container. */
final class VaultTestSupport {

    private VaultTestSupport() {
    }

    /** Must run before container construction, including setup invoked before Jupiter lifecycle methods. */
    static void assumeDockerAvailable() {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "Docker is unavailable; skipping container-dependent Vault tests");
    }
}
