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

import static apoc.export.cypher.ExportCypherTest.ExportCypherResults;
import static apoc.export.cypher.ExportCypherTest.ExportCypherResults.EXPECTED_CONSTRAINTS;
import static apoc.util.MapUtil.map;
import static apoc.util.TestContainerUtil.*;
import static apoc.util.TestUtil.readFileToString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import apoc.util.Neo4jContainerExtension;
import apoc.util.TestUtil;
import apoc.util.Util;
import java.io.File;
import java.util.List;
import java.util.stream.Stream;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.neo4j.driver.Session;

/**
 * @author as
 * @since 13.02.19
 */
public class ExportCypherEnterpriseFeaturesTest {

    private static Neo4jContainerExtension neo4jContainer;
    private static Session session;

    @BeforeClass
    public static void beforeAll() {
        neo4jContainer = createEnterpriseDB(List.of(ApocPackage.CORE), !TestUtil.isRunningInCI())
                .withInitScript("init_neo4j_export_csv.cypher");
        neo4jContainer.start();
        session = neo4jContainer.getSession();
    }

    @AfterClass
    public static void afterAll() {
        neo4jContainer.close();
    }

    private static void beforeTwoLabelsWithOneCompoundConstraintEach() {
        session.writeTransaction(tx -> {
            tx.run("CREATE CONSTRAINT compositeBase FOR (t:Base) REQUIRE (t.tenantId, t.id) IS NODE KEY");
            tx.commit();
            return null;
        });
        session.writeTransaction(tx -> {
            tx.run("CREATE (a:Person:Base {name: 'Phil', surname: 'Meyer', tenantId: 'neo4j', id: 'waBfk3z'}) "
                    + "CREATE (b:Person:Base {name: 'Silvia', surname: 'Jones', tenantId: 'random', id: 'waBfk3z'}) "
                    + "CREATE (a)-[:KNOWS]->(b)");
            tx.commit();
            return null;
        });
    }

    private static void afterTwoLabelsWithOneCompoundConstraintEach() {
        session.writeTransaction(tx -> {
            tx.run("MATCH (a:Person:Base) DETACH DELETE a");
            tx.commit();
            return null;
        });
        session.writeTransaction(tx -> {
            tx.run("DROP CONSTRAINT compositeBase");
            tx.commit();
            return null;
        });
    }

    @Test
    public void testExportWithCompoundConstraintCypherShell() {
        String fileName = "testCypherShellWithCompoundConstraint.cypher";
        testCall(
                session,
                "CALL apoc.export.cypher.all($file, $config)",
                map("file", fileName, "config", Util.map("format", "cypher-shell")),
                (r) -> assertExportStatement(
                        ExportCypherResults.EXPECTED_CYPHER_SHELL_WITH_COMPOUND_CONSTRAINT, fileName));
    }

    @Test
    public void testExportWithCompoundConstraintPlain() {
        String fileName = "testPlainFormatWithCompoundConstraint.cypher";
        testCall(
                session,
                "CALL apoc.export.cypher.all($file, $config)",
                map("file", fileName, "config", Util.map("format", "plain")),
                (r) -> assertExportStatement(
                        ExportCypherResults.EXPECTED_PLAIN_FORMAT_WITH_COMPOUND_CONSTRAINT, fileName));
    }

    @Test
    public void testExportWithCompoundConstraintNeo4jShell() {
        String fileName = "testNeo4jShellWithCompoundConstraint.cypher";
        testCall(
                session,
                "CALL apoc.export.cypher.all($file, $config)",
                map("file", fileName, "config", Util.map("format", "neo4j-shell")),
                (r) -> assertExportStatement(
                        ExportCypherResults.EXPECTED_NEO4J_SHELL_WITH_COMPOUND_CONSTRAINT, fileName));
    }

    @Test
    public void shouldHandleTwoLabelsWithOneCompoundConstraintEach() {
        final String query = "MATCH (a:Person:Base)-[r:KNOWS]-(b:Person) RETURN a, b, r";
        /* The bug was:
           UNWIND [{start: {name:"Phil", surname:"Meyer"}, end: {name:"Silvia", surname:"Jones"}, properties:{}}] AS row
           MATCH (start:Person{tenantId: row.start.tenantId, id: row.start.id, surname: row.start.surname, name: row.start.name})
           MATCH (end:Person{surname: row.end.surname, name: row.end.name})
           CREATE (start)-[r:KNOWS]->(end) SET r += row.properties;
        */
        final String expected =
                """
                UNWIND [{start: {name:"Phil", surname:"Meyer"}, end: {name:"Silvia", surname:"Jones"}, properties:{}}] AS row
                MATCH (start:Person{surname: row.start.surname, name: row.start.name})
                MATCH (end:Person{surname: row.end.surname, name: row.end.name})
                CREATE (start)-[r:KNOWS]->(end) SET r += row.properties""";

        try {
            beforeTwoLabelsWithOneCompoundConstraintEach();
            testCallInReadTransaction(
                    session,
                    "CALL apoc.export.cypher.query($query, $file, $config)",
                    Util.map("file", null, "query", query, "config", Util.map("format", "plain", "stream", true)),
                    (r) -> {
                        final String cypherStatements = (String) r.get("cypherStatements");
                        String unwind = Stream.of(cypherStatements.split(";"))
                                .map(String::trim)
                                .filter(s -> s.startsWith("UNWIND"))
                                .filter(s -> s.contains("Meyer"))
                                .skip(1)
                                .findFirst()
                                .orElse(null);
                        assertEquals(expected, unwind);
                    });
        } finally {
            afterTwoLabelsWithOneCompoundConstraintEach();
        }
    }

    private void assertExportStatement(String expectedStatement, String fileName) {
        // The constraints are exported in arbitrary order, so we cannot assert on the entire file
        String actual = readFileToString(new File(importFolder, fileName));
        MatcherAssert.assertThat(actual, Matchers.containsString(expectedStatement));
        EXPECTED_CONSTRAINTS.forEach(constraint ->
                assertTrue(String.format("Constraint '%s' not in result", constraint), actual.contains(constraint)));
    }
}
