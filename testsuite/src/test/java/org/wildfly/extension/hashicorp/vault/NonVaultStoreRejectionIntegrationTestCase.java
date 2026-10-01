/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.RunningMode;
import org.jboss.as.controller.capability.registry.RuntimeCapabilityRegistry;
import org.jboss.as.controller.capability.registry.CapabilityScope;
import org.jboss.as.controller.capability.registry.ImmutableCapabilityRegistry;
import org.jboss.as.controller.extension.ExtensionRegistry;
import org.jboss.as.controller.operations.common.Util;
import org.jboss.as.controller.registry.ManagementResourceRegistration;
import org.jboss.as.controller.registry.Resource;
import org.jboss.as.subsystem.test.AdditionalInitialization;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Integration test verifying that {@link VaultExpressionResolver} rejects a credential store
 * name that has no registered doohickey (credential-store API capability), even when a legitimate
 * HashiCorp Vault credential store is present in the same kernel.
 *
 * <p>A real Vault instance is started via Testcontainers and wired up as the subsystem's
 * {@code vault-store} credential store. The resolver uses {@code getCapabilityRuntimeAPI} to
 * retrieve the doohickey for a given store name; {@code file-store} has no registered doohickey
 * so the lookup throws {@link IllegalArgumentException}, which the resolver converts to an
 * {@link ExpressionResolver.ExpressionResolutionUserException} (WFLYHCVT0028). The test asserts:
 * <ul>
 *   <li>Resolving against {@code vault-store} (the Vault-backed store) succeeds.</li>
 *   <li>Resolving against {@code file-store} (no registered capability) is rejected with
 *       {@code WFLYHCVT0028} naming the file store.</li>
 * </ul>
 */
public class NonVaultStoreRejectionIntegrationTestCase extends SubsystemJUnit5TestCase {

    private static final String VAULT_TOKEN        = "myroot";
    private static final String VAULT_STORE_NAME   = "vault-store";
    private static final String FILE_STORE_NAME    = "file-store";
    private static final String TEST_ALIAS         = "integration?rejection_test";
    private static final String TEST_SECRET        = "top-secret-value";

    private static final PathAddress SUBSYSTEM_ADDRESS =
            PathAddress.pathAddress(PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress VAULT_STORE_ADDRESS =
            SUBSYSTEM_ADDRESS.append("credential-store", VAULT_STORE_NAME);

    private static VaultContainer<?> vault;

    private KernelServices kernelServices;
    private VaultExpressionResolver resolver;
    /** Captured at boot time; used by the mock context to answer getCapabilityRuntimeAPI. */
    private ImmutableCapabilityRegistry capabilityRegistry;

    // -------------------------------------------------------------------------
    // Container lifecycle (once per class)
    // -------------------------------------------------------------------------

    private static synchronized void ensureVaultStarted() {
        if (vault != null) return;
        vault = new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.21"))
                .withVaultToken(VAULT_TOKEN);
        vault.start();
    }

    @BeforeAll
    static void startVault() {
        ensureVaultStarted();
    }

    @AfterAll
    static void stopVault() {
        if (vault != null) {
            vault.stop();
            vault = null;
        }
    }

    // -------------------------------------------------------------------------
    // Subsystem wiring
    // -------------------------------------------------------------------------

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.DEFAULT) {
            @Override
            protected RunningMode getRunningMode() {
                return RunningMode.NORMAL;
            }

            @Override
            protected void initializeExtraSubystemsAndModel(ExtensionRegistry extensionRegistry,
                    Resource rootResource, ManagementResourceRegistration rootRegistration,
                    RuntimeCapabilityRegistry registry) {
                super.initializeExtraSubystemsAndModel(extensionRegistry, rootResource, rootRegistration, registry);
                // Capture the live registry reference so the mock context can call getCapabilityRuntimeAPI
                // after boot (when the credential-store doohickey has been registered).
                capabilityRegistry = registry;
            }
        };
    }

    @Override
    protected String getSubsystemXml() {
        ensureVaultStarted();
        return "<subsystem xmlns=\"urn:wildfly:hashicorp-vault:2.0\">\n"
                + "    <credential-store name=\"" + VAULT_STORE_NAME + "\""
                + " host-address=\"" + vault.getHttpHostAddress() + "\">\n"
                + "        <credential-reference clear-text=\"" + VAULT_TOKEN + "\"/>\n"
                + "    </credential-store>\n"
                + "</subsystem>";
    }

    // -------------------------------------------------------------------------
    // Per-test setup / teardown
    // -------------------------------------------------------------------------

    @BeforeEach
    public void bootKernelAndRegisterFileStore() throws Exception {
        kernelServices = createKernelServicesBuilder(createAdditionalInitialization())
                .setSubsystemXml(getSubsystemXml())
                .build();
        assertTrue(kernelServices.isSuccessfulBoot(),
                "Subsystem boot failed: " + kernelServices.getBootError());
        kernelServices.getContainer().awaitStability();
        resolver = new VaultExpressionResolver();

        // Store a test alias in the real Vault store so the positive assertion has something to resolve.
        // Remove first in case a previous run left it behind (Vault container is shared across tests).
        ModelNode removeStale = Util.createOperation("remove-alias", VAULT_STORE_ADDRESS);
        removeStale.get("alias").set(TEST_ALIAS);
        kernelServices.executeOperation(removeStale); // ignore outcome — alias may not exist yet

        ModelNode addAlias = Util.createOperation("add-alias", VAULT_STORE_ADDRESS);
        addAlias.get("alias").set(TEST_ALIAS);
        addAlias.get("secret-value").set(TEST_SECRET);
        ModelNode result = kernelServices.executeOperation(addAlias);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(),
                "add-alias on Vault store should succeed: " + result);

    }

    // -------------------------------------------------------------------------
    // Test methods
    // -------------------------------------------------------------------------

    /**
     * The positive side: the real Vault store resolves the alias successfully.
     * This confirms the test setup is correct before asserting the rejection.
     */
    @Test
    public void resolveExpressionSucceedsForVaultStore() {
        OperationContext ctx = mockContextRuntime();
        String resolved = resolver.resolveExpression(
                "${HC_VAULT::" + VAULT_STORE_NAME + ":" + TEST_ALIAS + "}", ctx);
        assertEquals(TEST_SECRET, resolved,
                "Vault store should resolve the alias to the stored secret");
    }

    /**
     * The key assertion: the resolver must reject {@code file-store} because no doohickey
     * (credential-store API capability) is registered for that name — only the vault-backed
     * {@code vault-store} has one. The resolver converts the missing capability to an
     * {@link ExpressionResolver.ExpressionResolutionUserException} (WFLYHCVT0030).
     */
    @Test
    public void resolveExpressionRejectsFileStoreEvenWhenVaultStoreIsPresent() {
        OperationContext ctx = mockContextRuntime();

        ExpressionResolver.ExpressionResolutionUserException ex = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression(
                        "${HC_VAULT::" + FILE_STORE_NAME + ":" + TEST_ALIAS + "}", ctx));

        assertTrue(ex.getMessage().contains("WFLYHCVT0030"),
                "Should reject the file store as non-Vault: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("'" + FILE_STORE_NAME + "'"),
                "Rejection message should identify the file store by name: " + ex.getMessage());
    }

    private OperationContext mockContextRuntime() {
        InvocationHandler h = (proxy, method, args) -> {
            if ("getCurrentStage".equals(method.getName())) {
                return OperationContext.Stage.RUNTIME;
            }
            if ("getCapabilityRuntimeAPI".equals(method.getName()) && args != null && args.length == 3) {
                String capabilityBaseName = (String) args[0];
                String dynamicPart        = (String) args[1];
                @SuppressWarnings("unchecked")
                Class<Object> apiType = (Class<Object>) args[2];
                String fullName = org.jboss.as.controller.capability.RuntimeCapability
                        .buildDynamicCapabilityName(capabilityBaseName, dynamicPart);
                return capabilityRegistry.getCapabilityRuntimeAPI(fullName, CapabilityScope.GLOBAL, apiType);
            }
            Class<?> rt = method.getReturnType();
            if (rt == boolean.class) return false;
            if (rt == int.class || rt == Integer.class) return 0;
            if (rt == long.class  || rt == Long.class)  return 0L;
            return null;
        };
        return (OperationContext) Proxy.newProxyInstance(
                OperationContext.class.getClassLoader(),
                new Class<?>[]{ OperationContext.class },
                h);
    }
}
