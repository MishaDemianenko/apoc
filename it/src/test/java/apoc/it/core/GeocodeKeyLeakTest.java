/*
 * Copyright (c) "Neo4j"
 * Neo4j Sweden AB [http://neo4j.com]
 *
 * This file is part of Neo4j.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package apoc.it.core;

import static apoc.util.MapUtil.map;
import static apoc.util.TestContainerUtil.createEnterpriseDB;
import static apoc.util.TestContainerUtil.testCall;
import static apoc.util.TestContainerUtil.testCallEmpty;
import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import apoc.util.Neo4jContainerExtension;
import apoc.util.TestContainerUtil;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.neo4j.driver.Session;

class GeocodeKeyLeakTest {

    private static final String ADMIN_KEY = "superSecretAdminKey";
    // nothing listens on port 1, so once the server key is substituted the request fails on the network
    // rather than on the missing key
    private static final String URL = "http://localhost:1/geocode/v1/json?q=PLACE&key=KEY";
    private static final String REVERSE_URL = "http://localhost:1/geocode/v1/json?q=LAT+LNG&key=KEY";
    private static final Map<String, Object> CALLER_CONFIG =
            map("provider", "opencage", "url", URL, "reverseUrl", REVERSE_URL);

    // every geocode procedure reaches the same supplier, so all three are expected to behave alike
    private static final List<String> GEOCODE_QUERIES = List.of(
            "CALL apoc.spatial.geocodeOnce('FRANCE', $config)",
            "CALL apoc.spatial.geocode('FRANCE', 1, true, $config)",
            "CALL apoc.spatial.reverseGeocode($lat, $lon, false, $config)");

    private static Neo4jContainerExtension neo4jContainer;
    private static Session adminSession;
    private static Driver userDriver;
    private static Session userSession;

    @BeforeAll
    static void beforeClass() {
        neo4jContainer = createEnterpriseDB(List.of(TestContainerUtil.ApocPackage.CORE), true)
                .withNeo4jConfig("apoc.spatial.geocode.opencage.key", ADMIN_KEY);
        neo4jContainer.start();

        adminSession = neo4jContainer.getSession();

        testCallEmpty(adminSession, "CREATE ROLE geocodeTest", emptyMap());
        testCallEmpty(
                adminSession,
                "CREATE USER geocodeUser SET PASSWORD 'password1234' SET PASSWORD CHANGE NOT REQUIRED",
                emptyMap());
        testCallEmpty(adminSession, "GRANT ROLE geocodeTest, reader TO geocodeUser", emptyMap());
        for (String procedure :
                List.of("apoc.spatial.geocodeOnce", "apoc.spatial.geocode", "apoc.spatial.reverseGeocode")) {
            testCallEmpty(adminSession, "GRANT EXECUTE PROCEDURE " + procedure + " ON DBMS TO geocodeTest", emptyMap());
        }

        userDriver = GraphDatabase.driver(neo4jContainer.getBoltUrl(), AuthTokens.basic("geocodeUser", "password1234"));
        userDriver.verifyConnectivity();
        userSession = userDriver.session();
    }

    @AfterAll
    static void afterClass() {
        if (userSession != null) userSession.close();
        if (userDriver != null) userDriver.close();
        if (adminSession != null) adminSession.close();
        if (neo4jContainer != null) neo4jContainer.close();
    }

    @Test
    void testNonAdminCallerSuppliedUrlDoesNotGetTheServerKey() {
        // the caller-supplied url template loses the server key, so the supplier is never built and
        // nothing is sent to the caller-chosen host
        for (String query : GEOCODE_QUERIES) {
            RuntimeException e = assertThrows(RuntimeException.class, () -> geocode(userSession, query));

            assertThat(e.getMessage()).contains("Missing 'key' for geocode provider");
        }
    }

    @Test
    void testAdminCallerSuppliedUrlStillGetsTheServerKey() {
        // an admin can read apoc.conf anyway, so the key is kept and the request goes out
        for (String query : GEOCODE_QUERIES) {
            RuntimeException e = assertThrows(RuntimeException.class, () -> geocode(adminSession, query));

            assertThat(e.getMessage()).doesNotContain("Missing 'key'");
        }
    }

    private static void geocode(Session session, String query) {
        testCall(session, query, map("config", CALLER_CONFIG, "lat", 48.8582532, "lon", 2.294287), r -> {});
    }
}
