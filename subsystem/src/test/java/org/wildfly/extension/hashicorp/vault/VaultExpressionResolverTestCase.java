/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;

import org.jboss.as.controller.ExpressionResolver;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.common.function.ExceptionFunction;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.password.interfaces.ClearPassword;


/**
 * Unit tests for {@link VaultExpressionResolver}.
 *
 * <p>The expression resolver parses expressions of the form {@code ${HC_VAULT::storeName:alias}},
 * splitting on the first {@code :} after the {@code HC_VAULT::} prefix to extract the credential store name
 * and the alias string. The alias is then passed verbatim to the credential store for retrieval.
 *
 * <p>These tests verify the resolver's own parsing logic — prefix detection, brace matching,
 * store/alias extraction, and stage validation. No actual Vault connectivity is involved;
 * a mock {@link OperationContext} is used throughout.
 *
 * <p>Actual alias format resolution (parsing {@code #}, {@code ?}, {@code @}, {@code engine=} etc.
 * into mount path, secret path, and key path) is the responsibility of the credential store implementation
 * in the upstream {@code wildfly-elytron-hashicorp-vault} library, tested by
 * {@code VaultAliasParsingTestCase} there. End-to-end resolution against a real Vault instance is
 * covered by {@code VaultExpressionResolverIntegrationTestCase} in the testsuite module.
 */
public class VaultExpressionResolverTestCase {

    private VaultExpressionResolver resolver;

    @BeforeEach
    public void setUp() {
        resolver = new VaultExpressionResolver();
    }

    @Test
    public void resolveExpressionReturnsNullForTooShortExpression() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME, null);
        assertNull(resolver.resolveExpression("${x::y}", ctx));
    }

    @Test
    public void resolveExpressionReturnsNullWhenNotWrappedInBraces() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME, null);
        assertNull(resolver.resolveExpression("HC_VAULT::store:alias", ctx));
        assertNull(resolver.resolveExpression("${HC_VAULT::store:alias", ctx));
        assertNull(resolver.resolveExpression("HC_VAULT::store:alias}", ctx));
    }

    @Test
    public void resolveExpressionReturnsNullForNonVaultPrefix() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME, null);
        assertNull(resolver.resolveExpression("${OTHER::store:alias}", ctx));
        assertNull(resolver.resolveExpression("${HC_VAULTX::store:alias}", ctx));
    }

    @Test
    public void resolveExpressionThrowsWhenAliasEmpty() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME, null);
        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression("${HC_VAULT::myStore:}", ctx));
        assertTrue(e.getMessage().contains("alias is empty"), "Message should mention alias empty");
    }

    @Test
    public void resolveExpressionThrowsServerExceptionInModelStage() {
        OperationContext ctx = mockContext(OperationContext.Stage.MODEL, null);
        ExpressionResolver.ExpressionResolutionServerException e = assertThrows(
                ExpressionResolver.ExpressionResolutionServerException.class,
                () -> resolver.resolveExpression("${HC_VAULT::myStore:myAlias}", ctx));
        assertTrue(e.getMessage().contains("MODEL"), "Message should mention MODEL");
    }

    /**
     * Verifies that when no doohickey is registered for the given store name
     * (simulated by {@code getCapabilityRuntimeAPI} throwing {@link IllegalArgumentException}),
     * the resolver throws a user-facing exception mentioning the store name.
     */
    @Test
    public void resolveExpressionThrowsUserExceptionWhenStoreNotInstalled() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME, null);
        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression("${HC_VAULT::noSuchStore:someAlias}", ctx));
        assertTrue(e.getMessage().contains("not installed") || e.getMessage().contains("not available"),
                "Message should mention not installed or not available");
    }

    /**
     * Verifies that when a doohickey <em>is</em> registered for the store name (simulated by the
     * mock returning a stub {@code ExceptionFunction} that provides a real in-memory
     * {@link CredentialStore} containing the expected alias), the resolver returns the secret value.
     *
     * <p>This is the core doohickey path: {@code getCapabilityRuntimeAPI} returns the function,
     * {@code apply(context)} is called, and the resulting store is queried. No MSC service
     * registry is consulted.</p>
     */
    @Test
    public void resolveExpressionUsesDoohickeyApiToResolveSecret() throws Exception {
        final String storeName = "myVault";
        final String alias = "#secret?password";
        final String expectedValue = "s3cr3t";

        // Build a real in-memory CredentialStore backed by MapCredentialStore.
        CredentialStore inMemoryStore = buildInMemoryStore(alias, expectedValue);

        // The doohickey is just an ExceptionFunction that returns the store.
        ExceptionFunction<OperationContext, CredentialStore, OperationFailedException> doohickey =
                ctx -> inMemoryStore;

        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME, doohickey);
        String result = resolver.resolveExpression("${HC_VAULT::" + storeName + ":" + alias + "}", ctx);
        assertEquals(expectedValue, result);
    }

    /**
     * Builds a real in-memory {@link CredentialStore} backed by {@code MapCredentialStore},
     * pre-populated with a single {@link PasswordCredential} at the given alias.
     */
    private static CredentialStore buildInMemoryStore(String alias, String secretValue) throws Exception {
        org.wildfly.security.credential.store.WildFlyElytronCredentialStoreProvider provider =
                org.wildfly.security.credential.store.WildFlyElytronCredentialStoreProvider.getInstance();
        CredentialStore store = CredentialStore.getInstance("MapCredentialStore", provider);
        store.initialize(java.util.Map.of(), null, new java.security.Provider[]{provider});
        ClearPassword cp = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secretValue.toCharArray());
        store.store(alias, new PasswordCredential(cp));
        return store;
    }

    @Test
    public void resolveExpressionThrowsOnNullExpression() {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME, null);
        assertThrows(IllegalArgumentException.class,
                () -> resolver.resolveExpression(null, ctx));
    }

    @Test
    public void resolveExpressionThrowsOnNullContext() {
        assertThrows(IllegalArgumentException.class,
                () -> resolver.resolveExpression("${HC_VAULT::s:a}", null));
    }

    /**
     * Verifies that the expression resolver correctly extracts alias strings containing
     * characters introduced by the new alias format (wildfly-elytron-hashicorp-vault PR #71):
     * {@code [engine=TYPE][@mount-path][#]secret-path?key-path}.
     *
     * <p><b>Scenario:</b> Each alias is wrapped into {@code ${HC_VAULT::myStore:<alias>}} and
     * passed to the resolver. Since the mock context has no credential store installed, the
     * resolver is expected to throw an {@link ExpressionResolver.ExpressionResolutionUserException}
     * with a message like:
     * <pre>
     * WFLYHCVT0028: Credential store 'myStore' is not installed for the expression: ${HC_VAULT::myStore:#secret?key}
     * </pre>
     *
     * <p><b>What this proves:</b> The resolver's colon-based split ({@code indexOf(':')}) correctly
     * separates the store name from the alias, even when the alias contains special characters
     * ({@code #}, {@code ?}, {@code @}, {@code /}, {@code .}, {@code =}, {@code %}-encoded sequences,
     * colons). If the store name is correctly extracted, the alias — being the complementary
     * substring after the same split — must also be correct.
     *
     * <p><b>What this does not cover:</b> Parsing of the alias into its components (engine type,
     * mount path, secret path, key path) and actual secret retrieval — those are tested in the
     * upstream library and in the integration testsuite respectively.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "#secret?key",
            "secret?key",
            "myapp/database?password",
            "#my.app.config?password",
            "#myapp?db.host",
            "#myapp?database/host",
            "#myapp?app/config/database/host",
            "#services?my.app/config.key",
            "engine=KVv1#secret?key",
            "@custom#secret?key",
            "engine=KVv2@team/vault#app.db.config?api.key",
            "#test%20path?password",
            "#test%23path?key",
            "#test%3Fpath?key",
            "@mount%2Fname#secret%20path?key",
            "@mount%40name#secret?key",
            "#a?b",
            "#my_app-v2?db_host-primary",
            "#123/456?789",
            "#secret?a/b/c/d/e",
            "#secret:path?key",
            "engine=KVv2@mount%20path#secret%23name?key%3Fname"
    })
    void resolveExpressionExtractsNewFormatAlias(String alias) {
        OperationContext ctx = mockContext(OperationContext.Stage.RUNTIME, null);
        String expression = "${HC_VAULT::myStore:" + alias + "}";
        ExpressionResolver.ExpressionResolutionUserException e = assertThrows(
                ExpressionResolver.ExpressionResolutionUserException.class,
                () -> resolver.resolveExpression(expression, ctx));
        assertInstanceOf(ExpressionResolver.ExpressionResolutionUserException.class, e);
        assertTrue(e.getMessage().contains("'myStore'"),
                "Store name should be correctly extracted from expression with alias '" + alias + "'");
    }

    /**
     * Creates a mock {@link OperationContext} for the given stage.
     *
     * @param stage     the stage returned by {@link OperationContext#getCurrentStage()}
     * @param doohickey when non-null, returned by {@code getCapabilityRuntimeAPI}; when null,
     *                  {@code getCapabilityRuntimeAPI} throws {@link IllegalArgumentException}
     *                  to simulate a store that is not registered.
     */
    private static OperationContext mockContext(OperationContext.Stage stage,
            ExceptionFunction<OperationContext, CredentialStore, OperationFailedException> doohickey) {
        ServiceRegistry registry = new ServiceRegistry() {
            @Override
            public ServiceController<?> getService(ServiceName name) {
                return null;
            }
            @Override
            public List<ServiceName> getServiceNames() {
                return Collections.emptyList();
            }
            @Override
            public ServiceController<?> getRequiredService(ServiceName name) {
                throw new IllegalStateException("No service: " + name);
            }
        };
        InvocationHandler h = new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                if ("getCurrentStage".equals(method.getName())) {
                    return stage;
                }
                if ("getCapabilityRuntimeAPI".equals(method.getName()) && args != null && args.length == 3) {
                    if (doohickey != null) {
                        return doohickey;
                    }
                    throw new IllegalArgumentException("No capability registered for: " + args[0] + "." + args[1]);
                }
                if ("getCapabilityServiceName".equals(method.getName()) && args != null && args.length == 3) {
                    return ServiceName.of("capability", (String) args[0], (String) args[1]);
                }
                if ("getServiceRegistry".equals(method.getName())) {
                    return registry;
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
