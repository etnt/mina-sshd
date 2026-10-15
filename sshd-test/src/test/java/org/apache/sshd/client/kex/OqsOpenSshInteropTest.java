/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.client.kex;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Collections;
import java.util.Locale;

import org.apache.sshd.AbstractContainerTestBase;
import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.DHFactory;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.ContainerFetchException;
import org.testcontainers.containers.ContainerLaunchException;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * Interoperability with the prebuilt OQS-OpenSSH image. No C compilation takes place during tests.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
class OqsOpenSshInteropTest extends AbstractContainerTestBase {

    private static final Logger LOG = LoggerFactory.getLogger(OqsOpenSshInteropTest.class);

    // After both architectures pass smoke-test.sh, replace this with the published multi-arch index digest.
    // Note: this digest predates the Alpine pin in docker/oqs-openssh/Dockerfile.
    // Switch to ghcr.io/apache when ASF Infra enables it. See docker/oqs-openssh/README.md.
    private static final String OQS_OPENSSH_IMAGE
            = "ghcr.io/etnt/mina-sshd-oqs-openssh@sha256:702c734e663283577e08b6f4f18910acb0b6cbf0a6fa36f9dd6a603124896a9b";

    @Test
    void hybridConnectivity() throws Exception {
        DHFactory factory = BuiltinDHFactories.mlkem768x25519;
        Assumptions.assumeTrue(factory.isSupported(), "Hybrid ML-KEM is not supported by this provider");
        connect(factory);
    }

    @Test
    void pureMlKem768() throws Exception {
        // The maintainer owns pure ML-KEM. Do not add a second implementation here.
        DHFactory factory = BuiltinDHFactories.fromFactoryName("mlkem768-sha256");
        Assumptions.assumeTrue(factory != null && factory.isSupported(),
                "Enable after the maintainer's pure ML-KEM factory lands");
        connect(factory);
    }

    private static boolean isImageUnavailable(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof ContainerFetchException || cause instanceof UnknownHostException) {
                return true;
            }
            String message = cause.getMessage();
            if (message != null) {
                message = message.toLowerCase(Locale.ROOT);
                if (message.contains("manifest unknown") || message.contains("pull access denied")
                        || message.contains("unauthorized") || message.contains("authentication required")) {
                    return true;
                }
            }
        }
        return false;
    }

    private void connect(DHFactory factory) throws Exception {
        Assumptions.assumeTrue(BuiltinSignatures.ed25519.isSupported(), "Ed25519 host keys are not supported");
        // Start manually so unsupported algorithms skip before pulling or starting the image.
        try (GenericContainer<?> server = new GenericContainer<>(DockerImageName.parse(OQS_OPENSSH_IMAGE))
                .withExposedPorts(22)
                // The image defaults to pure KEX only. Override it for the hybrid connectivity test.
                // Keep DEBUG3 in the image, but avoid flooding CI logs for these basic sessions.
                .withCommand("-o", "KexAlgorithms=" + factory.getName(), "-o", "LogLevel=VERBOSE")
                .waitingFor(Wait.forLogMessage(".*Server listening on.*port 22.*\\n", 1))
                .withStartupTimeout(Duration.ofMinutes(2))
                .withLogConsumer(new Slf4jLogConsumer(LOG))) {
            try {
                server.start();
            } catch (ContainerLaunchException | ContainerFetchException e) {
                if (!isImageUnavailable(e)) {
                    throw e;
                }
                Assumptions.abort("OQS-OpenSSH image not available: " + e.getMessage());
            }
            SshClient client = setupTestClient();
            client.setKeyExchangeFactories(Collections.singletonList(ClientBuilder.DH2KEX.apply(factory)));
            client.setSignatureFactories(Collections.singletonList(BuiltinSignatures.ed25519));
            client.start();
            try (ClientSession session = client.connect("test", server.getHost(), server.getMappedPort(22))
                    .verify(CONNECT_TIMEOUT).getSession()) {
                session.addPasswordIdentity("test"); // Default in docker/oqs-openssh/entrypoint.sh.
                session.auth().verify(AUTH_TIMEOUT);
                assertTrue(session.isAuthenticated(), "Password authentication failed");
                assertEquals(factory.getName(), session.getNegotiatedKexParameter(KexProposalOption.ALGORITHMS));
                assertEquals("CONNECTED_OK", session.executeRemoteCommand("echo CONNECTED_OK", DEFAULT_TIMEOUT).trim());
            } finally {
                client.stop();
            }
        }
    }
}
