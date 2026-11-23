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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package apoc.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.neo4j.graphdb.security.URLAccessChecker;

class FileUtilsWindowsPathTest {

    private static final URLAccessChecker ALLOW_ALL = url -> url;

    @Test
    void detectsWindowsDrivePaths() {
        assertTrue(FileUtils.isWindowsDrivePath("D:\\code\\my_repo\\data\\all_members.gml"));
        assertTrue(FileUtils.isWindowsDrivePath("c:/Users/me/file.graphml"));
        assertTrue(FileUtils.isWindowsDrivePath("C:"));
        assertFalse(FileUtils.isWindowsDrivePath("file:///tmp/file.graphml"));
        assertFalse(FileUtils.isWindowsDrivePath("file:C:/tmp/file.graphml"));
        assertFalse(FileUtils.isWindowsDrivePath("https://example.com/file"));
        assertFalse(FileUtils.isWindowsDrivePath("s3://bucket/file"));
        assertFalse(FileUtils.isWindowsDrivePath("/tmp/file"));
        assertFalse(FileUtils.isWindowsDrivePath(null));
    }

    @Test
    void windowsDrivePathIsAFile() {
        assertEquals(SupportedProtocols.file, FileUtils.from("D:\\code\\my_repo\\data\\all_members.gml"));
        assertEquals(SupportedProtocols.file, FileUtils.from("D:/code/my_repo/data/all_members.gml"));
        assertTrue(FileUtils.isFile("D:\\code\\my_repo\\data\\all_members.gml"));
    }

    @Test
    void getFileUrlKeepsWindowsDrivePath() throws Exception {
        String path = "D:\\code\\my_repo\\data\\all_members.gml";
        assertEquals(path, FileUtils.getFileUrl(path));
    }

    @Test
    void windowsDrivePathReachesFileLookup() {
        String path = "D:\\code\\does\\not\\exist.gml";
        IOException e = assertThrows(
                IOException.class,
                () -> FileUtils.getStreamConnection(SupportedProtocols.file, path, null, null, ALLOW_ALL));
        assertTrue(e.getMessage().startsWith("Cannot open file"), e.getMessage());
    }
}
