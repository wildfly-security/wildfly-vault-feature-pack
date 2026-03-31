/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.extension.hashicorp.vault;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;

import io.smallrye.certs.CertificateFiles;
import io.smallrye.certs.CertificateGenerator;
import io.smallrye.certs.CertificateRequest;
import io.smallrye.certs.Format;
import io.smallrye.certs.JksCertificateFiles;
import io.smallrye.certs.PemCertificateFiles;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import org.testcontainers.vault.VaultContainer;

/**
 * Vault container with TLS on port 8400 (HTTPS), based on smallrye-certs generated PEMs.
 *
 * When {@linkplain #VaultContainerHttps(String, boolean) mutual TLS} is required on 8400, readiness uses HTTP
 * {@code /v1/sys/health} on port 8200 from {@code vault server -dev} (Docker entrypoint {@code -dev-listen-address});
 */
public class VaultContainerHttps<SELF extends VaultContainerHttps<SELF>> extends VaultContainer<SELF> {

    private static final int HTTP_HEALTH_PORT = 8200;
    private static final int HTTPS_PORT = 8400;

    private static final String VAULT_CERT_NAME = "vault.crt";
    private static final String VAULT_CERT_KEY_NAME = "vault.key";
    private static final String CLIENT_CA_CERT_NAME = "client-ca.crt";

    private static final Path VAULT_CERT_CONTAINER_PATH = Path.of("/vault/certs");

    private static String buildVaultConfig(boolean requireMutualTls) {
        Path cert = VAULT_CERT_CONTAINER_PATH.resolve(VAULT_CERT_NAME).toAbsolutePath();
        Path key = VAULT_CERT_CONTAINER_PATH.resolve(VAULT_CERT_KEY_NAME).toAbsolutePath();
        Path clientCa = VAULT_CERT_CONTAINER_PATH.resolve(CLIENT_CA_CERT_NAME).toAbsolutePath();
        String mutual = requireMutualTls ? "true" : "false";
        return "listener \"tcp\" {\n"
                + "  address             = \"0.0.0.0:" + HTTPS_PORT + "\"\n"
                + "  tls_cert_file       = \"" + cert + "\"\n"
                + "  tls_key_file        = \"" + key + "\"\n"
                + "  tls_client_ca_file  = \"" + clientCa + "\"\n"
                + "  tls_require_and_verify_client_cert = " + mutual + "\n"
                + "}\n\n"
                + "storage \"file\" {\n"
                + "  path = \"/vault/data\"\n"
                + "}\n\n"
                + "ui = false\n\n"
                + "disable_mlock = true\n"
                + "api_addr = \"https://127.0.0.1:" + HTTPS_PORT + "\"\n";
    }

    private static final String ADMIN_POLICY_CONFIG = "path \"*\" {\n" +
            "  capabilities = [\"create\",\"read\",\"update\",\"delete\",\"list\",\"sudo\"]\n" +
            "}";

    private static final String ADMIN_POLICY_CONFIG_NAME = "admin-policy.hcl";
    private static final String VAULT_CONFIG_NAME = "config.hcl";

    private static final Path VAULT_CONFIG_CONTAINER_PATH = Path.of("/vault/config");

    private final Path generatedCertificatesDir;
    private static PemCertificateFiles serverPemCertificateFiles;

    private final Path generatedClientCertificatesDir;
    private static PemCertificateFiles clientPemCertificateFiles;
    private static JksCertificateFiles clientJksCertificateFiles;

    private final Path mountedVaultCertsDir;
    private final Path mountedVaultConfigDir;

    public VaultContainerHttps(String dockerImageName) throws IOException {
        this(dockerImageName, false);
    }

    /**
     * @param requireMutualTls if {@code true}, Vault requires a client certificate on the HTTPS listener (8400).
     *                         Readiness uses HTTP {@code /v1/sys/health} on 8200 from {@code vault server -dev}.
     */
    public VaultContainerHttps(String dockerImageName, boolean requireMutualTls) throws IOException {
        super(dockerImageName);

        final MountableFile certs;
        final MountableFile config;

        this.generatedCertificatesDir = Files.createTempDirectory("generated_certificates");
        this.generatedClientCertificatesDir = Files.createTempDirectory("generated_client_certificates");
        this.mountedVaultCertsDir = Files.createTempDirectory("vault_certs");
        this.mountedVaultConfigDir = Files.createTempDirectory("vault_config");

        try {
            prepareCertificatesForClientAuthentication(this.generatedClientCertificatesDir, this.mountedVaultCertsDir);
            prepareCertificatesForHttps(this.generatedCertificatesDir, this.mountedVaultCertsDir);
            certs = MountableFile.forHostPath(this.mountedVaultCertsDir, 0777);

            config = MountableFile.forHostPath(prepareVaultConfig(this.mountedVaultConfigDir, requireMutualTls), 0777);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        this.withCopyFileToContainer(certs, VAULT_CERT_CONTAINER_PATH.toAbsolutePath().toString())
                .withCopyFileToContainer(config, VAULT_CONFIG_CONTAINER_PATH.toAbsolutePath().toString())
                .withExposedPorts(HTTP_HEALTH_PORT, HTTPS_PORT)
                .withLogConsumer(new VaultContainerLogConsumer("HTTPS_VAULT"))
                .withInitCommand("policy write admin " + VAULT_CONFIG_CONTAINER_PATH.resolve(ADMIN_POLICY_CONFIG_NAME).toAbsolutePath())
                .withCommand("server", "-dev");

        if (requireMutualTls) {
            this.setWaitStrategy(Wait.forHttp("/v1/sys/health")
                    .forPort(HTTP_HEALTH_PORT)
                    .forStatusCode(200)
                    .forResponsePredicate(response -> response.contains("\"initialized\":true")));
        } else {
            this.setWaitStrategy(Wait.forHttps("/v1/sys/health")
                    .forPort(HTTPS_PORT)
                    .allowInsecure()
                    .forResponsePredicate(response -> response.contains("\"initialized\":true")));
        }
    }

    private static void prepareCertificatesForHttps(final Path certTmpDir, final Path vaultTmpCertDir) throws Exception {
        final CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PEM)
                .withFormat(Format.JKS);

        final List<CertificateFiles> certificateFiles = new CertificateGenerator(certTmpDir, true).generate(request);

        serverPemCertificateFiles = certificateFiles.stream()
                .filter(PemCertificateFiles.class::isInstance)
                .map(PemCertificateFiles.class::cast)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Expected PEM output from certificate generator"));

        final Path certPath = serverPemCertificateFiles.certFile();
        final Path keyPath = serverPemCertificateFiles.keyFile();

        Files.copy(certPath, vaultTmpCertDir.resolve(VAULT_CERT_NAME), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        Files.copy(keyPath, vaultTmpCertDir.resolve(VAULT_CERT_KEY_NAME), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    private static void prepareCertificatesForClientAuthentication(final Path certTmpDir, final Path vaultTmpCertDir) throws Exception {
        final CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PEM)
                .withFormat(Format.JKS);

        final List<CertificateFiles> certificateFiles = new CertificateGenerator(certTmpDir, true).generate(request);

        clientPemCertificateFiles = certificateFiles.stream()
                .filter(PemCertificateFiles.class::isInstance)
                .map(PemCertificateFiles.class::cast)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Expected PEM output from client certificate generator"));
        clientJksCertificateFiles = certificateFiles.stream()
                .filter(JksCertificateFiles.class::isInstance)
                .map(JksCertificateFiles.class::cast)
                .filter(JksCertificateFiles::client)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Expected client JKS from certificate generator"));

        String clientCaPem = Files.readString(clientPemCertificateFiles.trustFile(), StandardCharsets.UTF_8)
                + "\n"
                + Files.readString(clientPemCertificateFiles.serverTrustFile(), StandardCharsets.UTF_8);
        Files.writeString(vaultTmpCertDir.resolve(CLIENT_CA_CERT_NAME), clientCaPem, StandardCharsets.UTF_8);
    }

    private static Path prepareVaultConfig(final Path vaultConfigDir, boolean requireMutualTls) throws IOException {
        final Path vaultConfigFile = vaultConfigDir.resolve(VAULT_CONFIG_NAME);
        final Path adminPolicyConfigFile = vaultConfigDir.resolve(ADMIN_POLICY_CONFIG_NAME);
        Files.writeString(vaultConfigFile, buildVaultConfig(requireMutualTls));
        Files.writeString(adminPolicyConfigFile, ADMIN_POLICY_CONFIG);
        return vaultConfigDir;
    }

    public String composeHttpsHostAddress() {
        return String.format("https://127.0.0.1:%s", this.getMappedPort(HTTPS_PORT));
    }

    public Path getHttpsTrustFile() {
        return serverPemCertificateFiles.trustFile();
    }

    public PemCertificateFiles getClientCertificateFiles() {
        return clientPemCertificateFiles;
    }

    public Path getClientKeyStorePath() {
        return clientJksCertificateFiles.clientKeyStoreFile();
    }

    public String getClientKeyStorePassword() {
        return clientJksCertificateFiles.password();
    }

    public static String getClientCertificateKeyAlias() {
        return "test";
    }

    @Override
    public void close() {
        super.close();
        cleanupDir(this.generatedCertificatesDir);
        cleanupDir(this.generatedClientCertificatesDir);
        cleanupDir(this.mountedVaultCertsDir);
        cleanupDir(this.mountedVaultConfigDir);
    }

    public static void cleanupDir(Path dir) {
        if (dir == null || !Files.isDirectory(dir)) {
            return;
        }
        try {
            Files.walkFileTree(dir, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path d, IOException exc) throws IOException {
                    Files.deleteIfExists(d);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException ignored) {
            // ignored
        }
    }
}
