/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.util.function.Supplier;
import java.util.stream.Stream;

import org.jboss.as.arquillian.api.ServerSetupTask;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentest4j.TestAbortedException;
import org.testcontainers.DockerClientFactory;

/** Exercises the early setup entry points without a container engine or management client. */
public class DockerUnavailableTestCase {

    @BeforeAll
    static void requireUnavailableDocker() {
        assumeFalse(DockerClientFactory.instance().isDockerAvailable(),
                "These regression checks require an environment without Docker");
    }

    @ParameterizedTest(name = "{0}: embedded initialization aborts before container access")
    @MethodSource("embeddedTests")
    void embeddedInitializationSkips(String name, Supplier<SubsystemJUnit5TestCase> factory,
            Executable start, Executable stop) {
        SubsystemJUnit5TestCase test = factory.get();
        // This path bypasses @BeforeAll, as initialization through the subsystem harness can do.
        assertUnavailable(test::getSubsystemXml);
        assertUnavailable(start);
        assertDoesNotThrow(stop);
    }

    static Stream<Arguments> embeddedTests() {
        return Stream.of(
                Arguments.of("alias formats", (Supplier<SubsystemJUnit5TestCase>) AliasFormatFeatureIntegrationTestCase::new,
                        (Executable) AliasFormatFeatureIntegrationTestCase::startVault,
                        (Executable) AliasFormatFeatureIntegrationTestCase::stopVault),
                Arguments.of("credential store", (Supplier<SubsystemJUnit5TestCase>) CredentialStoreVaultIntegrationTestCase::new,
                        (Executable) CredentialStoreVaultIntegrationTestCase::startVault,
                        (Executable) CredentialStoreVaultIntegrationTestCase::stopVault),
                Arguments.of("expression resolver", (Supplier<SubsystemJUnit5TestCase>) VaultExpressionResolverIntegrationTestCase::new,
                        (Executable) VaultExpressionResolverIntegrationTestCase::startVault,
                        (Executable) VaultExpressionResolverIntegrationTestCase::stopVault),
                Arguments.of("complex aliases", (Supplier<SubsystemJUnit5TestCase>) VaultExpressionComplexAliasIntegrationTestCase::new,
                        (Executable) VaultExpressionComplexAliasIntegrationTestCase::startVault,
                        (Executable) VaultExpressionComplexAliasIntegrationTestCase::stopVault),
                Arguments.of("non-Vault rejection", (Supplier<SubsystemJUnit5TestCase>) NonVaultStoreRejectionIntegrationTestCase::new,
                        (Executable) NonVaultStoreRejectionIntegrationTestCase::startVault,
                        (Executable) NonVaultStoreRejectionIntegrationTestCase::stopVault));
    }

    @ParameterizedTest(name = "{0}: server setup aborts and cleanup tolerates skipped setup")
    @MethodSource("serverSetups")
    void serverSetupSkips(String name, ServerSetupTask setup) {
        // A skipped setup must neither access a management client nor require jboss.home for cleanup.
        assertUnavailable(() -> setup.setup(null, "unavailable-docker"));
        assertDoesNotThrow(() -> setup.tearDown(null, "unavailable-docker"));
    }

    static Stream<Arguments> serverSetups() {
        return Stream.of(
                Arguments.of("CRUD", new HashiCorpVaultCrudIntegrationTestCase.VaultSetup()),
                Arguments.of("credential reference", new HashiCorpVaultCredentialReferenceIntegrationTestCase.VaultSetup()),
                Arguments.of("restricted token", new HashiCorpVaultRestrictedTokenIntegrationTestCase.VaultSetup()),
                Arguments.of("reload", new HashiCorpVaultReloadAndAvailabilityIntegrationTestCase.VaultSetup()),
                Arguments.of("HTTPS", new HashiCorpVaultHttpsAuthenticationContextIntegrationTestCase.ElytronSetup()),
                Arguments.of("mutual TLS", new HashiCorpVaultHttpsMutualTlsAuthenticationContextIntegrationTestCase.ElytronSetup()));
    }

    private static void assertUnavailable(Executable action) {
        TestAbortedException aborted = assertThrows(TestAbortedException.class, action);
        assertTrue(aborted.getMessage().contains("Docker is unavailable"), aborted.getMessage());
    }
}
