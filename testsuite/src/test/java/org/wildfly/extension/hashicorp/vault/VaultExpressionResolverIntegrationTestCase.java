/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Integration tests for {@link VaultExpressionResolver} using Testcontainers Vault.
 */
public class VaultExpressionResolverIntegrationTestCase extends SubsystemJUnit5TestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append("credential-store", CREDENTIAL_STORE_NAME);

    private static VaultContainer<?> vault;
    private KernelServices kernelServices;
    private VaultExpressionResolver resolver;
    /** Captured at boot time; used by the mock context to answer getCapabilityRuntimeAPI. */
    private ImmutableCapabilityRegistry capabilityRegistry;

    /** Starts Testcontainers Vault once (also from {@link #getSubsystemXml()} when JUnit Platform skips {@code @BeforeClass}). */
    private static synchronized void ensureVaultStarted() {
        if (vault != null) {
            return;
        }
        vault = new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.21"))
                .withVaultToken(VAULT_TOKEN)
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vault.start();
    }

    @BeforeClass
    public static void startVault() {
        ensureVaultStarted();
    }

    @AfterClass
    public static void stopVault() {
        if (vault != null) {
            vault.stop();
            vault = null;
        }
    }

    @Override
    protected AdditionalInitialization createAdditionalInitialization() {
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.DEFAULT) {
            @Override
            protected org.jboss.as.controller.RunningMode getRunningMode() {
                return org.jboss.as.controller.RunningMode.NORMAL;
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
        String hostAddress = vault.getHttpHostAddress();
        return "<subsystem xmlns=\"urn:wildfly:hashicorp-vault:2.0\">\n"
                + "    <credential-store name=\"" + CREDENTIAL_STORE_NAME + "\" host-address=\"" + hostAddress + "\">\n"
                + "        <credential-reference clear-text=\"" + VAULT_TOKEN + "\"/>\n"
                + "    </credential-store>\n"
                + "</subsystem>";
    }

    @BeforeEach
    public void bootKernel() throws Exception {
        kernelServices = createKernelServicesBuilder(createAdditionalInitialization())
                .setSubsystemXml(getSubsystemXml())
                .build();
        assertTrue(kernelServices.isSuccessfulBoot(), "Subsystem boot failed: " + kernelServices.getBootError());
        kernelServices.getContainer().awaitStability();
        resolver = new VaultExpressionResolver();
    }

    @Test
    public void resolveExpressionReturnsStoredSecret() {
        String alias = "integration?resolver_test";
        String secretValue = "resolved-secret-value";

        ModelNode addAlias = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        addAlias.get("alias").set(alias);
        addAlias.get("secret-value").set(secretValue);
        ModelNode addResult = kernelServices.executeOperation(addAlias);
        assertEquals(SUCCESS, addResult.get(OUTCOME).asString(), "add-alias should succeed: " + addResult);

        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":" + alias + "}";
        OperationContext ctx = mockContextRuntime();
        String resolved = resolver.resolveExpression(expression, ctx);
        assertNotNull(resolved);
        assertEquals(secretValue, resolved);
    }

    @Test
    public void resolveExpressionThrowsWhenAliasNotFound() {
        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":nonexistent?missing}";
        OperationContext ctx = mockContextRuntime();

        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression(expression, ctx));
        assertTrue(e.getMessage().contains("not found"), "Message should mention not found or alias");
    }

    @Test
    public void resolveExpressionThrowsWhenStoreNotInstalled() {
        String expression = "${HC_VAULT::no-such-store:some?key}";
        OperationContext ctx = mockContextRuntime();

        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression(expression, ctx));
        assertTrue(e.getMessage().contains("not installed") || e.getMessage().contains("not available"),
                "Message should mention not installed or not available");
    }

    /**
     * Builds an OperationContext proxy that answers the calls VaultExpressionResolver makes:
     * {@code getCurrentStage}, {@code getCapabilityRuntimeAPI} (delegated to the live
     * capability registry captured at boot), and {@code getCapabilityServiceName}.
     */
    private OperationContext mockContextRuntime() {
        InvocationHandler h = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                if ("getCurrentStage".equals(method.getName())) {
                    return OperationContext.Stage.RUNTIME;
                }
                if ("getCapabilityRuntimeAPI".equals(method.getName()) && args != null && args.length == 3) {
                    String capabilityBaseName = (String) args[0];
                    String dynamicPart = (String) args[1];
                    @SuppressWarnings("unchecked")
                    Class<Object> apiType = (Class<Object>) args[2];
                    String fullName = org.jboss.as.controller.capability.RuntimeCapability
                            .buildDynamicCapabilityName(capabilityBaseName, dynamicPart);
                    return capabilityRegistry.getCapabilityRuntimeAPI(fullName, CapabilityScope.GLOBAL, apiType);
                }
                Class<?> rt = method.getReturnType();
                if (rt == boolean.class) return false;
                if (rt == int.class || rt == Integer.class) return 0;
                if (rt == long.class || rt == Long.class) return 0L;
                return null;
            }
        };
        return (OperationContext) Proxy.newProxyInstance(
                OperationContext.class.getClassLoader(),
                new Class<?>[] { OperationContext.class },
                h);
    }
}
