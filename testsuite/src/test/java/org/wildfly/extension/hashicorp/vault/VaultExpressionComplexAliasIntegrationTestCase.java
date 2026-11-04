/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.RunningMode;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.as.controller.capability.registry.CapabilityScope;
import org.jboss.as.controller.capability.registry.ImmutableCapabilityRegistry;
import org.jboss.as.controller.capability.registry.RuntimeCapabilityRegistry;
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
 * Integration tests for {@link VaultExpressionResolver} with complex alias formats
 * ({@code engine=}, {@code @mount}, nested keys) resolved against a live Vault.
 * <p>
 * The existing {@link VaultExpressionResolverIntegrationTestCase} only tests the plain
 * {@code x?y} alias form. This class covers the gap where complex alias forms are
 * parsed correctly but never resolved end-to-end through the expression mechanism.
 */
public class VaultExpressionComplexAliasIntegrationTestCase extends SubsystemJUnit5TestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-expr-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append(
            "credential-store", CREDENTIAL_STORE_NAME);

    private static VaultContainer<?> vault;
    private KernelServices kernelServices;
    private VaultExpressionResolver resolver;
    private ImmutableCapabilityRegistry capabilityRegistry;

    private static synchronized void ensureVaultStarted() {
        VaultTestSupport.assumeDockerAvailable();
        if (vault != null) {
            return;
        }
        vault = new VaultContainer<>(DockerImageName.parse(VaultImages.VAULT))
                .withVaultToken(VAULT_TOKEN)
                .withInitCommand(
                        "secrets enable -version=1 -path=secret-v1 kv",
                        "secrets enable -version=2 -path=custom kv"
                );
        vault.start();
    }

    @BeforeAll
    public static void startVault() {
        ensureVaultStarted();
    }

    @AfterAll
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
            protected RunningMode getRunningMode() {
                return RunningMode.NORMAL;
            }

            @Override
            protected void initializeExtraSubystemsAndModel(ExtensionRegistry extensionRegistry,
                    Resource rootResource, ManagementResourceRegistration rootRegistration,
                    RuntimeCapabilityRegistry registry) {
                super.initializeExtraSubystemsAndModel(extensionRegistry, rootResource, rootRegistration, registry);
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

    // =====================================================================
    // KVv1 engine with explicit mount
    // =====================================================================

    /**
     * Stores a secret using {@code engine=KVv1@secret-v1#path?key} and resolves it
     * via {@code ${HC_VAULT::store:alias}}.
     * <p><b>Passes when:</b> the expression resolves to the stored secret value.
     */
    @Test
    public void testResolveExpressionWithKVv1EngineAndMount() {
        String alias = "engine=KVv1@secret-v1#exprtest?v1_secret";
        String secretValue = "kvv1-resolved-value";

        addAliasSuccess(alias, secretValue);

        String resolved = resolveExpression(alias);
        assertEquals(secretValue, resolved,
                "Expression with engine=KVv1@secret-v1 should resolve to the stored secret");
    }

    // =====================================================================
    // Custom KVv2 mount
    // =====================================================================

    /**
     * Stores a secret using {@code @custom#path?key} and resolves it
     * via {@code ${HC_VAULT::store:alias}}.
     * <p><b>Passes when:</b> the expression resolves to the stored secret value.
     */
    @Test
    public void testResolveExpressionWithCustomMount() {
        String alias = "@custom#exprtest?custom_secret";
        String secretValue = "custom-mount-resolved";

        addAliasSuccess(alias, secretValue);

        String resolved = resolveExpression(alias);
        assertEquals(secretValue, resolved,
                "Expression with @custom mount should resolve to the stored secret");
    }

    /**
     * Stores a secret using {@code engine=KVv2@custom#path?key} and resolves it
     * via {@code ${HC_VAULT::store:alias}}.
     * <p><b>Passes when:</b> the expression resolves to the stored secret value.
     */
    @Test
    public void testResolveExpressionWithExplicitKVv2EngineAndCustomMount() {
        String alias = "engine=KVv2@custom#exprtest?explicit_v2";
        String secretValue = "explicit-v2-custom";

        addAliasSuccess(alias, secretValue);

        String resolved = resolveExpression(alias);
        assertEquals(secretValue, resolved,
                "Expression with engine=KVv2@custom should resolve to the stored secret");
    }

    // =====================================================================
    // Nested key paths
    // =====================================================================

    /**
     * Stores a secret using a nested key path {@code #path?a/b/c} and resolves it
     * via {@code ${HC_VAULT::store:alias}}.
     * <p><b>Passes when:</b> the expression resolves to the stored secret value.
     */
    @Test
    public void testResolveExpressionWithNestedKeyPath() {
        String alias = "#exprtest?database/credentials/password";
        String secretValue = "nested-key-resolved";

        addAliasSuccess(alias, secretValue);

        String resolved = resolveExpression(alias);
        assertEquals(secretValue, resolved,
                "Expression with nested key path ?a/b/c should resolve to the stored secret");
    }

    // =====================================================================
    // Multi-part secret path
    // =====================================================================

    /**
     * Stores a secret using a multi-part secret path {@code #app/database?key} and resolves it
     * via {@code ${HC_VAULT::store:alias}}.
     * <p><b>Passes when:</b> the expression resolves to the stored secret value.
     */
    @Test
    public void testResolveExpressionWithMultiPartSecretPath() {
        String alias = "#myapp/database?db_password";
        String secretValue = "multi-part-path-resolved";

        addAliasSuccess(alias, secretValue);

        String resolved = resolveExpression(alias);
        assertEquals(secretValue, resolved,
                "Expression with multi-part secret path should resolve to the stored secret");
    }

    // =====================================================================
    // Combined: engine + mount + nested key
    // =====================================================================

    /**
     * Stores a secret using the full combined format
     * {@code engine=KVv2@custom#app/config?database/host} and resolves it.
     * <p><b>Passes when:</b> the expression resolves to the stored secret value.
     */
    @Test
    public void testResolveExpressionWithFullCombinedFormat() {
        String alias = "engine=KVv2@custom#app/config?database/host";
        String secretValue = "full-combined-resolved";

        addAliasSuccess(alias, secretValue);

        String resolved = resolveExpression(alias);
        assertEquals(secretValue, resolved,
                "Expression with full combined format should resolve to the stored secret");
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private void addAliasSuccess(String alias, String secretValue) {
        ModelNode op = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        op.get("alias").set(alias);
        op.get("secret-value").set(secretValue);
        ModelNode result = kernelServices.executeOperation(op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(),
                "add-alias should succeed for alias '" + alias + "': " + result);
    }

    private String resolveExpression(String alias) {
        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":" + alias + "}";
        OperationContext ctx = mockContextRuntime();
        String resolved = resolver.resolveExpression(expression, ctx);
        assertNotNull(resolved, "Expression should resolve to a non-null value: " + expression);
        return resolved;
    }

    private OperationContext mockContextRuntime() {
        InvocationHandler h = (proxy, method, args) -> {
            if ("getCurrentStage".equals(method.getName())) {
                return OperationContext.Stage.RUNTIME;
            }
            if ("getCapabilityRuntimeAPI".equals(method.getName()) && args != null && args.length == 3) {
                String capabilityBaseName = (String) args[0];
                String dynamicPart = (String) args[1];
                @SuppressWarnings("unchecked")
                Class<Object> apiType = (Class<Object>) args[2];
                String fullName = RuntimeCapability.buildDynamicCapabilityName(capabilityBaseName, dynamicPart);
                return capabilityRegistry.getCapabilityRuntimeAPI(fullName, CapabilityScope.GLOBAL, apiType);
            }
            Class<?> rt = method.getReturnType();
            if (rt == boolean.class) return false;
            if (rt == int.class || rt == Integer.class) return 0;
            if (rt == long.class || rt == Long.class) return 0L;
            return null;
        };
        return (OperationContext) Proxy.newProxyInstance(
                OperationContext.class.getClassLoader(),
                new Class<?>[] { OperationContext.class },
                h);
    }
}
