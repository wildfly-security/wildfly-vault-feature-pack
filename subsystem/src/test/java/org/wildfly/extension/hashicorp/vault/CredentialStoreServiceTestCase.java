/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.PathElement;
import org.jboss.msc.Service;
import org.jboss.msc.service.ServiceBuilder;
import org.jboss.msc.service.ServiceContainer;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.ServiceTarget;
import org.junit.jupiter.api.Test;
import org.wildfly.extension.hashicorp.vault.CredentialStoreDefinition.VaultCredentialStoreDoohickey;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStoreProvider;

/**
 * Unit and MSC container tests for {@link CredentialStoreService} verifying service value publication
 * via {@link Consumer<CredentialStore>}, {@link Supplier<CredentialStore>}, and value clearing on stop.
 */
public class CredentialStoreServiceTestCase {

    private static VaultCredentialStoreDoohickey createDoohickeyWithStore(CredentialStore store) throws Exception {
        PathAddress address = PathAddress.pathAddress(
                PathElement.pathElement("subsystem", "hashicorp-vault"),
                PathElement.pathElement("credential-store", "test-store"));
        VaultCredentialStoreDoohickey doohickey = new VaultCredentialStoreDoohickey(address);
        Field valueField = VaultCredentialStoreDoohickey.class.getDeclaredField("value");
        valueField.setAccessible(true);
        valueField.set(doohickey, store);
        return doohickey;
    }

    @Test
    public void testDirectServiceLifecycleAndValuePublication() throws Exception {
        CredentialStore mockStore = CredentialStore.getInstance(
                "HashicorpVaultCredentialStore", HashicorpVaultCredentialStoreProvider.getInstance());
        VaultCredentialStoreDoohickey doohickey = createDoohickeyWithStore(mockStore);

        AtomicReference<CredentialStore> publishedStore = new AtomicReference<>();
        CredentialStoreService service = new CredentialStoreService(doohickey, publishedStore::set);

        // Before start, getValue() throws and consumer has not received a value
        assertNull(publishedStore.get());
        assertThrows(IllegalStateException.class, service::getValue);
        assertThrows(IllegalStateException.class, service::get);

        // Start publishes the store to both consumer and service getters
        service.start(null);
        assertSame(mockStore, publishedStore.get());
        assertSame(mockStore, service.getValue());
        assertSame(mockStore, service.get());

        // Stop clears consumer value, invalidates service getters, and resets doohickey
        service.stop(null);
        assertNull(publishedStore.get());
        assertThrows(IllegalStateException.class, service::getValue);
        assertThrows(IllegalStateException.class, service::get);
        assertNull(doohickey.cachedValue());
    }

    @Test
    public void testMscContainerValuePublicationAndAliases() throws Exception {
        CredentialStore mockStore = CredentialStore.getInstance(
                "HashicorpVaultCredentialStore", HashicorpVaultCredentialStoreProvider.getInstance());
        VaultCredentialStoreDoohickey doohickey = createDoohickeyWithStore(mockStore);

        ServiceContainer container = ServiceContainer.Factory.create("test-container");
        try {
            ServiceTarget target = container.subTarget();
            ServiceName serviceName = ServiceName.of("wildfly", "security", "credential-store", "test-store");
            ServiceName privateName = ServiceName.of("org", "wildfly", "extension", "hashicorp", "vault", "test-store");

            ServiceBuilder<?> builder = target.addService();
            Consumer<CredentialStore> storeConsumer = builder.provides(serviceName, privateName);
            CredentialStoreService service = new CredentialStoreService(doohickey, storeConsumer);
            builder.setInstance(service);
            ServiceController<?> controller = builder.install();

            // Create a dependent service that requires both the primary and alias capability names
            ServiceName depServiceName = ServiceName.of("test", "dependent");
            ServiceBuilder<?> depBuilder = target.addService();
            depBuilder.provides(depServiceName);
            Supplier<CredentialStore> primarySupplier = depBuilder.requires(serviceName);
            Supplier<CredentialStore> aliasSupplier = depBuilder.requires(privateName);
            depBuilder.setInstance(Service.NULL);
            ServiceController<?> depController = depBuilder.install();

            container.awaitStability();
            assertSame(ServiceController.State.UP, controller.getState());
            assertSame(ServiceController.State.UP, depController.getState());

            // Primary capability requirement receives the published credential store
            assertSame(mockStore, primarySupplier.get());

            // Alias capability requirement receives the same published credential store
            assertSame(mockStore, aliasSupplier.get());

            // Service instance getters also return the store
            assertSame(mockStore, service.getValue());
            assertSame(mockStore, service.get());

            // Stopping the store service invalidates dependent suppliers and resets the doohickey
            controller.setMode(ServiceController.Mode.NEVER);
            container.awaitStability();
            assertSame(ServiceController.State.DOWN, controller.getState());
            assertThrows(IllegalStateException.class, primarySupplier::get);
            assertThrows(IllegalStateException.class, aliasSupplier::get);
            assertNull(doohickey.cachedValue());
            assertThrows(IllegalStateException.class, service::getValue);
            assertThrows(IllegalStateException.class, service::get);
        } finally {
            container.shutdown();
            container.awaitTermination();
        }
    }
}
