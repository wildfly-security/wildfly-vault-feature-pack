/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESULT;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.List;

import org.jboss.as.arquillian.container.ManagementClient;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.client.ModelControllerClient;
import org.jboss.as.version.Stability;
import org.jboss.dmr.ModelNode;
import org.junit.jupiter.api.Test;

/**
 * Tests for stability-dependent alias formats without starting WildFly or Vault.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CrudAliasFixtureTestCase {

    @Test
    public void testFormatsFollowActualServerStability() throws Exception {
        for (Stability stability : Stability.values()) {
            ManagementClient client = client(operation -> {
                assertEquals("read-attribute", operation.get("operation").asString());
                assertEquals(PathAddress.pathAddress("core-service", "server-environment").toModelNode(),
                        operation.get("address"));
                assertEquals("stability", operation.get("name").asString());
                ModelNode response = success();
                response.get(RESULT).set(stability.toString());
                return response;
            });
            List<String> inputs = HashiCorpVaultCrudIntegrationTestCase.aliasFormats(client).stream()
                    .map(format -> format.format("#tree/branch?key")).toList();
            List<String> expected = stability == Stability.DEFAULT
                    ? List.of("#tree/branch?key", "tree/branch?key")
                    : List.of("#tree/branch?key", "tree/branch.key");
            assertEquals(expected, inputs, "Wrong formats at " + stability);
        }
    }

    @Test
    public void testStabilityReadFailureIsReported() {
        ManagementClient client = client(operation -> failed());
        AssertionError failure = assertThrows(AssertionError.class,
                () -> HashiCorpVaultCrudIntegrationTestCase.aliasFormats(client));
        assertTrue(failure.getMessage().contains("Reading server stability"));
    }

    private static ModelNode success() {
        ModelNode response = new ModelNode();
        response.get(OUTCOME).set(SUCCESS);
        return response;
    }

    private static ModelNode failed() {
        ModelNode response = new ModelNode();
        response.get(OUTCOME).set("failed");
        return response;
    }

    private static ManagementClient client(OperationExecutor executor) {
        ModelControllerClient controller = (ModelControllerClient) Proxy.newProxyInstance(
                ModelControllerClient.class.getClassLoader(), new Class<?>[] { ModelControllerClient.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("execute") && args[0] instanceof ModelNode operation) {
                        return executor.execute(operation);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        return new ManagementClient(controller, "127.0.0.1", 9990, "remote+http");
    }

    @FunctionalInterface
    private interface OperationExecutor {
        ModelNode execute(ModelNode operation) throws IOException;
    }
}
