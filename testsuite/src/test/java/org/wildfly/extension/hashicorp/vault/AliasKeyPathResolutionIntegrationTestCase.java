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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.as.controller.ExpressionResolver;
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
import org.jboss.dmr.ModelType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

/**
 * Integration tests for the key path semantics of the structured alias format provided by
 * {@code wildfly-elytron-hashicorp-vault} (wildfly-elytron-hashicorp-vault PR #107).
 * <p>
 * The key path of an alias ({@code #secret-path?key-path}) is split on an unencoded {@code /} <em>before</em> each
 * segment is URL-decoded exactly once, so that:
 * <ul>
 *   <li>{@code ?database/host} is nested traversal, {@code data["database"]["host"]}</li>
 *   <li>{@code ?database%2Fhost} is the literal key {@code database/host}</li>
 *   <li>{@code ?database%252Fhost} is the literal key {@code database%2Fhost}</li>
 * </ul>
 * Secrets are seeded and verified directly through the Vault HTTP API, and aliases are exercised through the
 * subsystem's {@code add-alias}, {@code remove-alias} and {@code read-aliases} operations and through
 * {@code ${HC_VAULT::store:alias}} expression resolution.
 */
public class AliasKeyPathResolutionIntegrationTestCase extends SubsystemJUnit5TestCase {

    private static final String VAULT_TOKEN = "myroot";
    private static final String CREDENTIAL_STORE_NAME = "vault-keypath-store";
    private static final PathAddress SUBSYSTEM_ADDRESS = PathAddress.pathAddress(
            PathElement.pathElement("subsystem", VaultExtension.SUBSYSTEM_NAME));
    private static final PathAddress CREDENTIAL_STORE_ADDRESS = SUBSYSTEM_ADDRESS.append(
            "credential-store", CREDENTIAL_STORE_NAME);

    /** A secret holding a nested key and two literal keys that differ only in how a slash is spelled. */
    private static final String SLASH_AND_PERCENT_SECRET = """
            {
              "database/host": "literal-slash",
              "database": { "host": "nested" },
              "database%2Fhost": "literal-percent"
            }
            """;

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
    // Reading: nested traversal vs literal slash vs literal percent
    // =====================================================================

    /**
     * An unencoded {@code /} traverses nested JSON, {@code %2F} is a literal slash in a key name and {@code %252F}
     * is the literal text {@code %2F}. All three can exist in the same secret without conflict.
     */
    @Test
    public void testSlashAndPercentSpellingsResolveToDistinctValues() throws Exception {
        seedSecret("keypath-slash", SLASH_AND_PERCENT_SECRET);

        assertEquals("nested", resolve("#keypath-slash?database/host"));
        assertEquals("literal-slash", resolve("#keypath-slash?database%2Fhost"));
        assertEquals("literal-percent", resolve("#keypath-slash?database%252Fhost"));
    }

    /** {@code %2F} and {@code %2f} are equivalent. */
    @Test
    public void testPercentEncodedSlashIsCaseInsensitive() throws Exception {
        seedSecret("keypath-case", """
                { "database/host": "literal-slash" }
                """);

        assertEquals("literal-slash", resolve("#keypath-case?database%2Fhost"));
        assertEquals("literal-slash", resolve("#keypath-case?database%2fhost"));
    }

    /** The key path is decoded once only: {@code %252F} is never decoded a second time into a slash. */
    @Test
    public void testPercentEncodedPercentIsNotDecodedTwice() throws Exception {
        seedSecret("keypath-double", """
                { "database": { "host": "nested" }, "database%2Fhost": "literal-percent" }
                """);

        assertEquals("literal-percent", resolve("#keypath-double?database%252Fhost"));
    }

    /** A slash encoded inside one segment of a nested path stays in that segment. */
    @Test
    public void testEncodedSlashInsideNestedSegment() throws Exception {
        seedSecret("keypath-mixed", """
                { "config": { "a/b": "slash-in-segment", "a": { "b": "traversed" } } }
                """);

        assertEquals("slash-in-segment", resolve("#keypath-mixed?config/a%2Fb"));
        assertEquals("traversed", resolve("#keypath-mixed?config/a/b"));
    }

    /** Dots in key names are not special, both in a simple lookup and inside nested segments. */
    @Test
    public void testDotsInKeyNames() throws Exception {
        seedSecret("keypath-dots", """
                { "db.host": "dotted", "my.app": { "config.key": "nested-dotted" } }
                """);

        assertEquals("dotted", resolve("#keypath-dots?db.host"));
        assertEquals("nested-dotted", resolve("#keypath-dots?my.app/config.key"));
    }

    // =====================================================================
    // Reading: other special characters
    // =====================================================================

    /** Characters that mean something in an alias are written percent-encoded in a key name. */
    @Test
    public void testSpecialCharactersInKeyNames() throws Exception {
        seedSecret("keypath-special", """
                {
                  "a b": "space",
                  "a+b": "plus",
                  "a%b": "percent",
                  "a?b": "question",
                  "a#b": "hash"
                }
                """);

        assertEquals("space", resolve("#keypath-special?a%20b"));
        assertEquals("plus", resolve("#keypath-special?a%2Bb"));
        assertEquals("percent", resolve("#keypath-special?a%25b"));
        assertEquals("question", resolve("#keypath-special?a%3Fb"));
        assertEquals("hash", resolve("#keypath-special?a%23b"));
    }

    /** An unencoded {@code +} is decoded as a space. */
    @Test
    public void testUnencodedPlusInKeyPathIsASpace() throws Exception {
        seedSecret("keypath-plus", """
                { "a b": "space", "a+b": "plus" }
                """);

        assertEquals("space", resolve("#keypath-plus?a+b"));
        assertEquals("plus", resolve("#keypath-plus?a%2Bb"));
    }

    /** Spaces, percent signs and plus signs in the secret path reach Vault unchanged. */
    @Test
    public void testSpecialCharactersInSecretPath() throws Exception {
        seedSecret("my app/100%dir/a+b", """
                { "key": "special-path-value" }
                """);

        assertEquals("special-path-value", resolve("#my%20app/100%25dir/a%2Bb?key"));
    }

    // =====================================================================
    // Reading: values and objects
    // =====================================================================

    /** Numbers, booleans and arrays are returned as their JSON text. */
    @Test
    public void testNonStringValuesResolveAsJsonText() throws Exception {
        seedSecret("keypath-types", """
                { "port": 5432, "flag": true, "list": ["a", "b"], "nested": { "port": 8080 } }
                """);

        assertEquals("5432", resolve("#keypath-types?port"));
        assertEquals("true", resolve("#keypath-types?flag"));
        assertEquals("[\"a\",\"b\"]", resolve("#keypath-types?list"));
        assertEquals("8080", resolve("#keypath-types?nested/port"));
    }

    /** A key path that ends at a JSON object, or at a JSON null, is not a credential and resolves to nothing. */
    @Test
    public void testObjectAndNullValuesDoNotResolve() throws Exception {
        seedSecret("keypath-object", """
                { "database": { "host": "nested" }, "nothing": null }
                """);

        assertUnresolvable("#keypath-object?database");
        assertUnresolvable("#keypath-object?nothing");
        assertUnresolvable("#keypath-object?database/missing");
        assertUnresolvable("#keypath-object?database/host/too-deep");
        assertEquals("nested", resolve("#keypath-object?database/host"));
    }

    // =====================================================================
    // Listing: read-aliases returns aliases that can be passed back to retrieve
    // =====================================================================

    /**
     * {@code read-aliases} lists every leaf value in its encoded form, including values in nested objects but not
     * the objects themselves, and every listed alias resolves back to the value it was listed for.
     */
    @Test
    public void testReadAliasesListsEncodedAliasesThatRoundTrip() throws Exception {
        seedSecret("keypath-list", SLASH_AND_PERCENT_SECRET);

        Set<String> aliases = readAliases("#keypath-list", false);

        assertEquals(Set.of(
                "#keypath-list?database/host",
                "#keypath-list?database%2Fhost",
                "#keypath-list?database%252Fhost"), aliases);
        assertFalse(aliases.contains("#keypath-list?database"), "An object must not be listed as an alias");

        Map<String, String> expected = Map.of(
                "#keypath-list?database/host", "nested",
                "#keypath-list?database%2Fhost", "literal-slash",
                "#keypath-list?database%252Fhost", "literal-percent");
        for (String alias : aliases) {
            assertEquals(expected.get(alias), resolve(alias), "Listed alias should read back its own value: " + alias);
        }
    }

    /** Special characters in secret paths and key names are encoded in listed aliases and round trip. */
    @Test
    public void testReadAliasesRecursiveEncodesSpecialCharactersAndRoundTrips() throws Exception {
        seedSecret("keypath list/50%off/a+b", """
                { "k/1": "slash", "k 2": "space", "k+3": "plus", "k%4": "percent" }
                """);

        Set<String> aliases = readAliases("#keypath%20list", true);

        Map<String, String> expected = Map.of(
                "#keypath%20list/50%25off/a%2Bb?k%2F1", "slash",
                "#keypath%20list/50%25off/a%2Bb?k%202", "space",
                "#keypath%20list/50%25off/a%2Bb?k%2B3", "plus",
                "#keypath%20list/50%25off/a%2Bb?k%254", "percent");
        assertEquals(expected.keySet(), aliases);
        for (String alias : aliases) {
            assertEquals(expected.get(alias), resolve(alias), "Listed alias should read back its own value: " + alias);
        }
    }

    // =====================================================================
    // Writing: store and remove change only the targeted value
    // =====================================================================

    /**
     * {@code add-alias} writes only the value at the key path. Siblings at every level keep their value and their
     * JSON type, nested objects stay objects, and missing intermediate objects are created.
     */
    @Test
    public void testAddAliasChangesOnlyTheTargetedValue() throws Exception {
        seedSecret("keypath-store", """
                {
                  "database": { "host": "nested", "port": 5432 },
                  "database/host": "literal-slash",
                  "flag": true,
                  "list": ["a", "b"]
                }
                """);

        addAliasSuccess("#keypath-store?database/user", "nested-added");
        addAliasSuccess("#keypath-store?database%2Fport", "literal-added");
        addAliasSuccess("#keypath-store?created/deep/leaf", "created");

        ModelNode data = readSecret("keypath-store");
        assertEquals("nested", data.get("database").get("host").asString());
        assertEquals(5432, data.get("database").get("port").asInt());
        assertNotEquals(ModelType.STRING, data.get("database").get("port").getType(), "Number must keep its JSON type");
        assertEquals("literal-slash", data.get("database/host").asString());
        assertEquals(ModelType.BOOLEAN, data.get("flag").getType(), "Boolean must keep its JSON type");
        assertEquals(ModelType.LIST, data.get("list").getType(), "Array must keep its JSON type");

        assertEquals("nested-added", data.get("database").get("user").asString());
        assertEquals("literal-added", data.get("database/port").asString());
        assertFalse(data.get("database").has("database/port"), "A literal slash key must not be written as nested");
        assertEquals("created", data.get("created").get("deep").get("leaf").asString());

        assertEquals("nested-added", resolve("#keypath-store?database/user"));
        assertEquals("literal-added", resolve("#keypath-store?database%2Fport"));
    }

    /** {@code add-alias} for a key that already exists is rejected whichever way the slash is spelled. */
    @Test
    public void testAddAliasRejectsExistingKeyForEachSpelling() throws Exception {
        seedSecret("keypath-dup", SLASH_AND_PERCENT_SECRET);

        for (String alias : new String[] {
                "#keypath-dup?database/host", "#keypath-dup?database%2Fhost", "#keypath-dup?database%252Fhost" }) {
            ModelNode result = addAlias(alias, "duplicate");
            assertEquals("failed", result.get(OUTCOME).asString(), "Duplicate add should fail for " + alias + ": " + result);
            assertTrue(result.get(FAILURE_DESCRIPTION).asString().contains("already exists"),
                    "Should mention 'already exists': " + result.get(FAILURE_DESCRIPTION).asString());
        }
    }

    /** {@code remove-alias} deletes only the value at the key path and leaves siblings and parents in place. */
    @Test
    public void testRemoveAliasDeletesOnlyTheTargetedValue() throws Exception {
        seedSecret("keypath-remove", """
                {
                  "database": { "host": "nested", "port": "5432" },
                  "database/host": "literal-slash",
                  "keep": "me"
                }
                """);

        removeAliasSuccess("#keypath-remove?database%2Fhost");
        ModelNode afterLiteral = readSecret("keypath-remove");
        assertFalse(afterLiteral.has("database/host"), "Literal key should be removed");
        assertEquals("nested", afterLiteral.get("database").get("host").asString(), "Nested value must survive");
        assertEquals("me", afterLiteral.get("keep").asString());

        removeAliasSuccess("#keypath-remove?database/host");
        ModelNode afterNested = readSecret("keypath-remove");
        assertEquals("5432", afterNested.get("database").get("port").asString(), "Nested sibling must survive");
        assertFalse(afterNested.get("database").has("host"), "Nested value should be removed");
        assertEquals("me", afterNested.get("keep").asString());
    }

    /** A special-character key written through {@code add-alias} lands in Vault under its decoded name. */
    @Test
    public void testAddAliasWithSpecialCharactersStoresDecodedKeyName() throws Exception {
        addAliasSuccess("#keypath-special-add?a%20b%2Fc%25d%2Be", "stored");

        ModelNode data = readSecret("keypath-special-add");
        assertTrue(data.has("a b/c%d+e"), "Key should be stored under its decoded name: " + data);
        assertEquals("stored", data.get("a b/c%d+e").asString());
        assertEquals("stored", resolve("#keypath-special-add?a%20b%2Fc%25d%2Be"));
    }

    // =====================================================================
    // Validation
    // =====================================================================

    /** An unencoded empty key path segment is invalid; an encoded slash alone is a valid literal key. */
    @Test
    public void testEmptyKeyPathSegmentsAreRejected() throws Exception {
        for (String alias : new String[] {
                "#keypath-empty?database//host", "#keypath-empty?database/", "#keypath-empty?/host" }) {
            ModelNode result = addAlias(alias, "should-not-matter");
            assertEquals("failed", result.get(OUTCOME).asString(), "Empty segment should be rejected for " + alias + ": " + result);
        }

        addAliasSuccess("#keypath-empty?%2F", "just-a-slash");
        assertEquals("just-a-slash", readSecret("keypath-empty").get("/").asString());
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

    private void assertUnresolvable(String alias) {
        String expression = "${HC_VAULT::" + CREDENTIAL_STORE_NAME + ":" + alias + "}";
        assertThrows(ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression(expression, mockContextRuntime()),
                "Alias should not resolve: " + alias);
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

    private Set<String> readAliases(String path, boolean recursive) {
        ModelNode op = Util.createOperation("read-aliases", CREDENTIAL_STORE_ADDRESS);
        op.get("path").set(path);
        op.get("recursive").set(recursive);
        ModelNode result = kernelServices.executeOperation(op);
        assertEquals(SUCCESS, result.get(OUTCOME).asString(), "read-aliases should succeed: " + result);
        return result.get(RESULT).asList().stream().map(ModelNode::asString).collect(Collectors.toSet());
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
