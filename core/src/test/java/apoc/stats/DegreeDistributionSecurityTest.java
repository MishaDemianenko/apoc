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
package apoc.stats;

import static org.assertj.core.api.Assertions.assertThat;

import apoc.util.TestUtil;
import com.neo4j.test.extension.EnterpriseDbmsExtension;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.configuration.GraphDatabaseSettings;
import org.neo4j.dbms.api.DatabaseManagementService;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Transaction;
import org.neo4j.internal.kernel.api.connectioninfo.ClientConnectionInfo;
import org.neo4j.internal.kernel.api.security.LoginContext;
import org.neo4j.kernel.api.KernelTransaction;
import org.neo4j.kernel.api.security.AuthManager;
import org.neo4j.kernel.api.security.AuthToken;
import org.neo4j.kernel.api.security.exception.InvalidAuthTokenException;
import org.neo4j.kernel.internal.GraphDatabaseAPI;
import org.neo4j.test.TestDatabaseManagementServiceBuilder;
import org.neo4j.test.extension.ExtensionCallback;
import org.neo4j.test.extension.Inject;

/**
 * Asserts that {@code apoc.stats.degrees} only reports what the calling user is allowed to read: the scan and the
 * degree counts must honour the caller's security context instead of running with {@code AUTH_DISABLED}.
 */
@EnterpriseDbmsExtension(createDatabasePerTest = false, configurationCallback = "configure")
class DegreeDistributionSecurityTest {

    private static final String RESTRICTED_USER = "restricted";
    private static final String RESTRICTED_PASSWORD = "password";

    @Inject
    GraphDatabaseService db;

    @Inject
    DatabaseManagementService dbms;

    @ExtensionCallback
    void configure(TestDatabaseManagementServiceBuilder builder) {
        builder.setConfig(GraphDatabaseSettings.auth_enabled, true);
    }

    @BeforeAll
    void setUp() {
        TestUtil.registerProcedure(db, DegreeDistribution.class);

        // :Foo is visible to the restricted user, :Hidden is not; :BAR is visible, :SECRET is not.
        db.executeTransactionally("CREATE (f:Foo) WITH f UNWIND range(1, 2) AS i CREATE (f)-[:BAR]->(f)");
        db.executeTransactionally("CREATE (h:Hidden) WITH h UNWIND range(1, 7) AS i CREATE (h)-[:BAR]->(h)");
        db.executeTransactionally("MATCH (f:Foo) WITH f UNWIND range(1, 3) AS i CREATE (f)-[:SECRET]->(f)");

        GraphDatabaseService systemDb = dbms.database(GraphDatabaseSettings.SYSTEM_DATABASE_NAME);
        systemDb.executeTransactionally("CREATE ROLE restrictedRole");
        systemDb.executeTransactionally(
                "CREATE USER " + RESTRICTED_USER + " SET PASSWORD '" + RESTRICTED_PASSWORD + "' CHANGE NOT REQUIRED");
        systemDb.executeTransactionally("GRANT ROLE restrictedRole TO " + RESTRICTED_USER);
        systemDb.executeTransactionally("GRANT ACCESS ON DATABASE * TO restrictedRole");
        systemDb.executeTransactionally("GRANT TRAVERSE ON GRAPH * NODES * TO restrictedRole");
        systemDb.executeTransactionally("GRANT TRAVERSE ON GRAPH * RELATIONSHIPS * TO restrictedRole");
        systemDb.executeTransactionally("DENY TRAVERSE ON GRAPH * NODES Hidden TO restrictedRole");
        systemDb.executeTransactionally("DENY TRAVERSE ON GRAPH * RELATIONSHIPS SECRET TO restrictedRole");
    }

    @Test
    void adminSeesEveryRelationshipTypeAndEveryNode() {
        List<Map<String, Object>> rows = degrees(LoginContext.AUTH_DISABLED, "*");

        assertThat(typesOf(rows)).containsExactlyInAnyOrder("BAR", "BAR", "SECRET", "SECRET");

        // the :Hidden node has 7 :BAR relationships, so it dominates the outgoing :BAR statistics
        Map<String, Object> bar = row(rows, "BAR", "OUTGOING");
        assertThat(bar.get("total")).isEqualTo(9L);
        assertThat(bar.get("max")).isEqualTo(7L);
    }

    @Test
    void deniedRelationshipTypeIsAbsentForRestrictedUser() throws InvalidAuthTokenException {
        assertThat(typesOf(degrees(restrictedLoginContext(), "*"))).containsExactlyInAnyOrder("BAR", "BAR");
    }

    @Test
    void restrictedUserOnlySeesDegreesOfNodesTheyMayTraverse() throws InvalidAuthTokenException {
        Map<String, Object> bar = row(degrees(restrictedLoginContext(), "*"), "BAR", "OUTGOING");

        // only the :Foo node is visible, and it has 2 :BAR relationships; the 7 :BAR relationships of the
        // denied :Hidden node must not contribute to the statistics
        assertThat(bar.get("total")).isEqualTo(2L);
        assertThat(bar.get("min")).isEqualTo(2L);
        assertThat(bar.get("max")).isEqualTo(2L);
        assertThat(bar.get("mean")).isEqualTo(2.0d);
    }

    private List<Map<String, Object>> degrees(LoginContext loginContext, String types) {
        try (Transaction tx = ((GraphDatabaseAPI) db).beginTransaction(KernelTransaction.Type.EXPLICIT, loginContext)) {
            return tx.execute("CALL apoc.stats.degrees($types)", Map.of("types", types)).stream()
                    .toList();
        }
    }

    private LoginContext restrictedLoginContext() throws InvalidAuthTokenException {
        AuthManager authManager =
                ((GraphDatabaseAPI) db).getDependencyResolver().resolveDependency(AuthManager.class);
        return authManager.login(
                AuthToken.newBasicAuthToken(RESTRICTED_USER, RESTRICTED_PASSWORD),
                ClientConnectionInfo.EMBEDDED_CONNECTION);
    }

    private static List<String> typesOf(List<Map<String, Object>> rows) {
        return rows.stream().map(row -> (String) row.get("type")).toList();
    }

    private static Map<String, Object> row(List<Map<String, Object>> rows, String type, String direction) {
        return rows.stream()
                .filter(row -> type.equals(row.get("type")) && direction.equals(row.get("direction")))
                .findFirst()
                .orElseThrow();
    }
}
