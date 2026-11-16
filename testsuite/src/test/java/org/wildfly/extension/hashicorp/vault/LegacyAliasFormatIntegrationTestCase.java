/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILURE_DESCRIPTION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

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
 * Integration tests for the legacy dot-separated alias format ({@code secret-path.key}), which is only accepted at
 * {@link Stability#COMMUNITY} stability or above.
 * <p>
 * wildfly-elytron-hashicorp-vault PR #107 changed how the key path of a <em>new</em> format alias is split and decoded,
 * but states that legacy handling must remain identical to 1.1.0.CR3. These tests pin that legacy behavior, and where
 * it differs from the new format they assert both sides:
 * <ul>
 *   <li>the alias is split on its <b>last</b> dot, wherever that is: {@code my.app/config} is secret {@code my},
 *       key {@code app/config}</li>
 *   <li>the default mount is always used, so a leading {@code secret/} is part of the secret path</li>
 *   <li>the key is URL-decoded <em>before</em> it is split on {@code /}, so {@code %2F} is nested traversal (in the
 *       new format it is a literal slash)</li>
 *   <li>an unencoded {@code +} is a space</li>
 * </ul>
 */
public class LegacyAliasFormatIntegrationTestCase extends SubsystemJUnit5TestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-legacy-store";
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
                .withVaultToken(VAULT_TOKEN);
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
        return new AdditionalInitialization.ManagementAdditionalInitialization(Stability.COMMUNITY) {
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
    protected String getSubsystemXml() throws IOException {
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
    // Reading
    // =====================================================================

    /** {@code secret.key} reads {@code key} from the secret {@code secret} on the default mount. */
    @Test
    public void testSimpleLegacyAlias() throws Exception {
        seedSecret("legacy-simple", """
                { "password": "legacy-value" }
                """);

        assertEquals("legacy-value", resolve("legacy-simple.password"));
    }

    /** A legacy alias addresses the same value as the equivalent new format alias. */
    @Test
    public void testLegacyAliasEqualsNewFormatAlias() throws Exception {
        seedSecret("legacy-same", """
                { "key": "same-value" }
                """);

        assertEquals(resolve("#legacy-same?key"), resolve("legacy-same.key"));
    }

    /** Slashes in the part before the last dot are part of the secret path. */
    @Test
    public void testLegacyAliasWithMultiPartSecretPath() throws Exception {
        seedSecret("legacy/app/database", """
                { "password": "multi-part" }
                """);

        assertEquals("multi-part", resolve("legacy/app/database.password"));
    }

    /** Dots before the last dot belong to the secret path, so only the final dot separates the key. */
    @Test
    public void testLegacyAliasSplitsOnLastDot() throws Exception {
        seedSecret("my.app.config", """
                { "db": "dotted-secret-path" }
                """);

        assertEquals("dotted-secret-path", resolve("my.app.config.db"));
    }

    /**
     * The alias is split on its last dot even when that dot is before a slash: {@code my.app/config} is secret
     * {@code my} and key {@code app/config}. The new format needs {@code my.app/config?key} for such names.
     */
    @Test
    public void testLegacyLastDotBeforeSlashSplitsSecretAndNestedKey() throws Exception {
        seedSecret("my", """
                { "app": { "config": "split-at-last-dot" } }
                """);

        assertEquals("split-at-last-dot", resolve("my.app/config"));
    }

    /**
     * Legacy aliases always use the default mount: the {@code secret/} prefix is not interpreted as a mount, it
     * becomes part of the secret path, so {@code secret/in-mount.key} reads the secret {@code secret/in-mount}.
     */
    @Test
    public void testLegacyMountPrefixBecomesPartOfSecretPath() throws Exception {
        seedSecret("secret/in-mount", """
                { "key": "prefix-is-path" }
                """);
        seedSecret("in-mount", """
                { "key": "not-this-one" }
                """);

        assertEquals("prefix-is-path", resolve("secret/in-mount.key"));
        assertEquals("not-this-one", resolve("in-mount.key"));
    }

    /** The secret path of a legacy alias is URL-decoded. */
    @Test
    public void testLegacyAliasSecretPathIsUrlDecoded() throws Exception {
        seedSecret("legacy space/50%off", """
                { "key": "decoded-path" }
                """);

        assertEquals("decoded-path", resolve("legacy%20space/50%25off.key"));
    }

    // =====================================================================
    // Legacy key decoding differs from the new format
    // =====================================================================

    /**
     * The legacy key is decoded <em>before</em> it is split on {@code /}, so {@code %2F} is nested traversal. This is
     * the opposite of the new format, where {@code %2F} in a key path is a literal slash.
     */
    @Test
    public void testLegacyEncodedSlashIsNestedTraversalUnlikeNewFormat() throws Exception {
        seedSecret("legacy-slash", """
                { "k": { "z": "nested" }, "k/z": "literal-slash" }
                """);

        assertEquals("nested", resolve("legacy-slash.k%2Fz"), "Legacy %2F is nested traversal");
        assertEquals("nested", resolve("legacy-slash.k/z"), "Legacy / is nested traversal");
        assertEquals("literal-slash", resolve("#legacy-slash?k%2Fz"), "New format %2F is a literal slash");
        assertEquals("nested", resolve("#legacy-slash?k/z"), "New format / is nested traversal");
    }

    /** In a legacy key an unencoded {@code +} is a space, and {@code %2B} is a plus. */
    @Test
    public void testLegacyKeyPlusIsSpace() throws Exception {
        seedSecret("legacy-plus", """
                { "a b": "space", "a+b": "plus" }
                """);

        assertEquals("space", resolve("legacy-plus.a+b"));
        assertEquals("space", resolve("legacy-plus.a%20b"));
        assertEquals("plus", resolve("legacy-plus.a%2Bb"));
    }

    // =====================================================================
    // Writing and removing
    // =====================================================================

    /** {@code add-alias} and {@code remove-alias} accept a legacy alias and address the same stored value. */
    @Test
    public void testAddAndRemoveLegacyAlias() throws Exception {
        addAliasSuccess("legacy-write.key", "written");

        ModelNode data = readSecret("legacy-write");
        assertEquals("written", data.get("key").asString());
        assertEquals("written", resolve("legacy-write.key"));
        assertEquals("written", resolve("#legacy-write?key"));

        ModelNode duplicate = addAlias("legacy-write.key", "duplicate");
        assertEquals("failed", duplicate.get(OUTCOME).asString(), "Duplicate add should fail: " + duplicate);
        assertTrue(duplicate.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                "Should mention 'already exists': " + duplicate.get(FAILURE_DESCRIPTION).asString());

        removeAliasSuccess("legacy-write.key");
        assertThrowsOnResolve("legacy-write.key");
    }

    /** A legacy key containing an encoded slash is written as a nested value, as in 1.1.0.CR3. */
    @Test
    public void testAddLegacyAliasWithEncodedSlashWritesNestedValue() throws Exception {
        addAliasSuccess("legacy-nested-write.a%2Fb", "nested-written");

        ModelNode data = readSecret("legacy-nested-write");
        assertFalse(data.has("a/b"), "Legacy %2F must not be stored as a literal slash key: " + data);
        assertEquals("nested-written", data.get("a").get("b").asString());
    }

    /** A legacy alias written with {@code add-alias} is listed by {@code read-aliases} in the new format. */
    @Test
    public void testReadAliasesListsLegacyAliasInNewFormat() throws Exception {
        addAliasSuccess("legacy-listed.key", "listed");

        ModelNode op = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        op.get("path").set("#legacy-listed");
        op.get("recursive").set(false);
        ModelNode result = kernelServices.executeOperation(op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(), "read-aliases should succeed: " + result);
        Set<String> aliases = result.get(RESULT).asList().stream().map(ModelNode::asString).collect(Collectors.toSet());
        assertEquals(Set.of("#legacy-listed?key"), aliases);
    }

    // =====================================================================
    // Validation
    // =====================================================================

    /** An alias with no new format indicator and no dot is neither format, so it is rejected. */
    @Test
    public void testAliasWithoutDotOrDelimiterIsRejected() throws Exception {
        ModelNode result = addAlias("nodothere", "should-not-matter");
        assertEquals("failed", result.get(OUTCOME).asString(), "Alias without a dot should be rejected: " + result);
    }

    /** A legacy alias must have both a secret path and a key. */
    @Test
    public void testLegacyAliasWithEmptySecretOrKeyIsRejected() throws Exception {
        for (String alias : new String[] { "trailing-dot.", ".leading-dot" }) {
            ModelNode result = addAlias(alias, "should-not-matter");
            assertEquals("failed", result.get(OUTCOME).asString(), "Should be rejected: " + alias + ": " + result);
        }
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private String resolve(String alias) {
        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":" + alias + "}";
        String resolved = resolver.resolveExpression(expression, mockContextRuntime());
        assertNotNull(resolved, "Expression should resolve to a non-null value: " + expression);
        return resolved;
    }

    private void assertThrowsOnResolve(String alias) {
        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":" + alias + "}";
        try {
            resolver.resolveExpression(expression, mockContextRuntime());
        } catch (org.jboss.as.controller.ExpressionResolver.ExpressionResolutionUserException expected) {
            return;
        }
        throw new AssertionError("Alias should not resolve: " + alias);
    }

    private ModelNode addAlias(String alias, String secretValue) {
        ModelNode op = Util.createOperation("add-alias", CREDENTIAL_STORE_ADDRESS);
        op.get("alias").set(alias);
        op.get("secret-value").set(secretValue);
        return kernelServices.executeOperation(op);
    }

    private void addAliasSuccess(String alias, String secretValue) {
        ModelNode result = addAlias(alias, secretValue);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(), "add-alias should succeed for '" + alias + "': " + result);
    }

    private void removeAliasSuccess(String alias) {
        ModelNode op = Util.createOperation("remove-alias", CREDENTIAL_STORE_ADDRESS);
        op.get("alias").set(alias);
        ModelNode result = kernelServices.executeOperation(op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(), "remove-alias should succeed for '" + alias + "': " + result);
    }

    /** Writes a KV v2 secret directly through the Vault HTTP API, bypassing the credential store. */
    private static void seedSecret(String secretPath, String dataJson) throws IOException, InterruptedException {
        String body = "{\"data\":" + dataJson + "}";
        HttpRequest request = HttpRequest.newBuilder(secretUri(secretPath))
                .header("X-Vault-Token", VAULT_TOKEN)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertTrue(response.statusCode() / 100 == 2, "Seeding '" + secretPath + "' should succeed: " + response.body());
    }

    /** Reads the current data of a KV v2 secret directly through the Vault HTTP API. */
    private static ModelNode readSecret(String secretPath) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(secretUri(secretPath))
                .header("X-Vault-Token", VAULT_TOKEN)
                .GET()
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "Reading '" + secretPath + "' should succeed: " + response.body());
        return ModelNode.fromJSONString(response.body()).get("data", "data");
    }

    private static URI secretUri(String secretPath) {
        String encodedPath = Arrays.stream(secretPath.split("/", -1))
                .map(segment -> URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20"))
                .collect(Collectors.joining("/"));
        return URI.create(vault.getHttpHostAddress() + "/v1/secret/data/" + encodedPath);
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
