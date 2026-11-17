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
 * {@link Stability#COMMUNITY} stability or a level that enables it.
 * <p>
 * The 1.1.0.Final library preserves the literal legacy key behavior of 1.0.1.Final. These tests pin that behavior, and where
 * it differs from the new format they assert both sides:
 * <ul>
 *   <li>the alias is split on its <b>last</b> dot, wherever that is: {@code my.app/config} is secret {@code my},
 *       literal key {@code app/config}; trailing dots are discarded before splitting</li>
 *   <li>the first path segment selects the mount; paths without a slash use the default mount</li>
 *   <li>keys are not decoded or split: {@code /}, {@code %2F}, and {@code +} remain literal</li>
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

        assertEquals("multi-part", resolve("secret/legacy/app/database.password"));
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
     * {@code my} and literal key {@code app/config}.
     */
    @Test
    public void testLegacyLastDotBeforeSlashSplitsSecretAndLiteralKey() throws Exception {
        seedSecret("my", """
                { "app/config": "split-at-last-dot", "app": { "config": "nested" } }
                """);

        assertEquals("split-at-last-dot", resolve("my.app/config"));
        assertEquals("split-at-last-dot", resolve("#my?app%2Fconfig"));
        assertEquals("nested", resolve("#my?app/config"));
    }

    /**
     * The first legacy path segment selects the mount, so {@code secret/in-mount.key} reads {@code in-mount}
     * on the {@code secret} mount, without duplicating the mount prefix.
     */
    @Test
    public void testLegacyMountPrefixSelectsMount() throws Exception {
        seedSecret("secret/in-mount", """
                { "key": "duplicated-mount" }
                """);
        seedSecret("in-mount", """
                { "key": "mount-qualified" }
                """);

        assertEquals("mount-qualified", resolve("secret/in-mount.key"));
        assertEquals("mount-qualified", resolve("in-mount.key"));
        assertEquals("mount-qualified", resolve("@secret#in-mount?key"));
        assertEquals("duplicated-mount", resolve("#secret/in-mount?key"));
    }

    /** The secret path of a legacy alias is URL-decoded. */
    @Test
    public void testLegacyAliasSecretPathIsUrlDecoded() throws Exception {
        seedSecret("legacy space/50%off/a+b", """
                { "key": "decoded-path" }
                """);

        assertEquals("decoded-path", resolve("secret/legacy%20space/50%25off/a+b.key"));
    }

    // =====================================================================
    // Legacy key decoding differs from the new format
    // =====================================================================

    /**
     * Legacy keys remain literal. The three slash spellings select distinct values, while modern aliases
     * decode each key segment and use an unencoded slash for traversal.
     */
    @Test
    public void testLegacySlashAndPercentAreLiteralUnlikeNewFormat() throws Exception {
        seedSecret("legacy-slash", """
                { "k": { "z": "nested" }, "k/z": "literal-slash", "k%2Fz": "literal-percent" }
                """);

        assertEquals("literal-percent", resolve("legacy-slash.k%2Fz"), "Legacy %2F stays literal");
        assertEquals("literal-slash", resolve("legacy-slash.k/z"), "Legacy / stays literal");
        assertEquals("literal-percent", resolve("#legacy-slash?k%252Fz"));
        assertEquals("literal-slash", resolve("#legacy-slash?k%2Fz"), "New format %2F is a literal slash");
        assertEquals("nested", resolve("#legacy-slash?k/z"), "New format / is nested traversal");
    }

    /** Legacy keys retain plus signs and percent escapes verbatim. */
    @Test
    public void testLegacyKeyPlusAndEscapesAreLiteral() throws Exception {
        seedSecret("legacy-plus", """
                { "a b": "space", "a+b": "plus", "a%20b": "percent-space", "a%2Bb": "percent-plus" }
                """);

        assertEquals("space", resolve("legacy-plus.a b"));
        assertEquals("plus", resolve("legacy-plus.a+b"));
        assertEquals("percent-space", resolve("legacy-plus.a%20b"));
        assertEquals("percent-plus", resolve("legacy-plus.a%2Bb"));
    }

    /** Markers inside a legacy key do not select modern parsing or URL decoding. */
    @Test
    public void testLegacyKeyMarkersAndMalformedEscapesAreLiteral() throws Exception {
        seedSecret("legacy-markers", """
                { "a?b": "question", "a#b": "hash", "a@b": "at", "a%zz": "percent" }
                """);

        assertEquals("question", resolve("legacy-markers.a?b"));
        assertEquals("hash", resolve("legacy-markers.a#b"));
        assertEquals("at", resolve("legacy-markers.a@b"));
        assertEquals("percent", resolve("legacy-markers.a%zz"));
        assertEquals("question", resolve("#legacy-markers?a%3Fb"));
    }

    /** Trailing dots are discarded before the last separating dot is selected. */
    @Test
    public void testLegacyAliasDiscardsTrailingDots() throws Exception {
        seedSecret("legacy-trailing", """
                { "key": "trailing-dots" }
                """);

        assertEquals("trailing-dots", resolve("legacy-trailing.key."));
        assertEquals("trailing-dots", resolve("legacy-trailing.key..."));
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

    /** A legacy key containing an encoded slash is written and removed as a literal key, preserving siblings. */
    @Test
    public void testAddAndRemoveLegacyAliasWithEncodedSlashUseLiteralKey() throws Exception {
        seedSecret("legacy-nested-write", """
                { "a": { "b": "nested" }, "a/b": "literal-slash" }
                """);
        addAliasSuccess("legacy-nested-write.a%2Fb", "percent-written");

        ModelNode data = readSecret("legacy-nested-write");
        assertEquals("percent-written", data.get("a%2Fb").asString());
        assertEquals("literal-slash", data.get("a/b").asString());
        assertEquals("nested", data.get("a").get("b").asString());
        assertEquals("percent-written", resolve("#legacy-nested-write?a%252Fb"));

        removeAliasSuccess("legacy-nested-write.a%2Fb");
        data = readSecret("legacy-nested-write");
        assertFalse(data.has("a%2Fb"), "Only the literal percent key should be removed: " + data);
        assertEquals("literal-slash", data.get("a/b").asString());
        assertEquals("nested", data.get("a").get("b").asString());
        assertThrowsOnResolve("legacy-nested-write.a%2Fb");
    }

    /** A legacy alias written with {@code add-alias} is listed by {@code read-aliases} in the new format. */
    @Test
    public void testReadAliasesListsLegacyAliasInNewFormat() throws Exception {
        addAliasSuccess("legacy-listed.key", "listed");
        addAliasSuccess("legacy-listed.a/b", "slash");
        addAliasSuccess("legacy-listed.a%2Fb", "percent");

        ModelNode op = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        op.get("path").set("#legacy-listed");
        op.get("recursive").set(false);
        ModelNode result = kernelServices.executeOperation(op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(), "read-aliases should succeed: " + result);
        Set<String> aliases = result.get(RESULT).asList().stream().map(ModelNode::asString).collect(Collectors.toSet());
        assertEquals(Set.of("#legacy-listed?key", "#legacy-listed?a%2Fb", "#legacy-listed?a%252Fb"), aliases);
        assertEquals("listed", resolve("#legacy-listed?key"));
        assertEquals("slash", resolve("#legacy-listed?a%2Fb"));
        assertEquals("percent", resolve("#legacy-listed?a%252Fb"));
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

    /** A legacy alias must have both a secret path and a key after trailing dots are discarded. */
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
