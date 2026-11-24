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
package apoc.hashing;

import apoc.util.Util;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.neo4j.graphdb.Entity;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Path;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.ResourceIterable;
import org.neo4j.graphdb.Transaction;
import org.neo4j.logging.Log;
import org.neo4j.procedure.Context;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.UserFunction;

public class Fingerprinting {

    @Context
    public Transaction tx;

    @Context
    public Log log;

    @UserFunction("apoc.hashing.fingerprint")
    @Description(
            "Calculates a MD5 checksum over a `NODE` or `RELATIONSHIP` (identical entities share the same checksum).\n"
                    + "Unsuitable for cryptographic use-cases.")
    public String fingerprint(
            @Name(value = "object", description = "A node or relationship to hash.") Object thing,
            @Name(
                            value = "excludedPropertyKeys",
                            defaultValue = "[]",
                            description = "Property keys to exclude from the hashing.")
                    List<String> excludedPropertyKeys) {
        FingerprintingConfig config = new FingerprintingConfig(Util.map(
                "allNodesDisallowList",
                excludedPropertyKeys,
                "allRelsDisallowList",
                excludedPropertyKeys,
                "mapDisallowList",
                excludedPropertyKeys,
                "strategy",
                FingerprintingConfig.FingerprintStrategy.EAGER.toString()));
        return fingerprint(thing, config);
    }

    @UserFunction("apoc.hashing.fingerprinting")
    @Description("""
            Calculates a MD5 checksum over a `NODE` or `RELATIONSHIP` (identical entities share the same checksum).
            Unlike `apoc.hashing.fingerprint()`, this function supports a number of config parameters.
            Unsuitable for cryptographic use-cases.""")
    public String fingerprinting(
            @Name(value = "object", description = "A node or relationship to hash.") Object thing,
            @Name(value = "config", defaultValue = "{}", description = """
                    {
                        digestAlgorithm = "MD5" :: STRING,
                        strategy = "LAZY" :: STRING,
                        nodeAllowMap = [] :: MAP<STRING, LIST<STRING>>,
                        relAllowMap = [] :: MAP<STRING, LIST<STRING>>,
                        relDisallowMap = [] :: MAP<STRING, LIST<STRING>>,
                        mapAllowList = [] :: LIST<STRING>,
                        mapDisallowList = [] :: LIST<STRING>,
                        allNodesAllowList = [] :: LIST<STRING>,
                        allNodesDisallowList = [] :: LIST<STRING>,
                        allRelsAllowList = [] :: LIST<STRING>,
                        allRelsDisallowList = [] :: LIST<STRING>
                    }""") Map<String, Object> conf) {
        FingerprintingConfig config = new FingerprintingConfig(conf);
        return fingerprint(thing, config);
    }

    private String fingerprint(Object thing, FingerprintingConfig config) {
        return withMessageDigest(config, md -> fingerprint(md, thing, config));
    }

    private void fingerprint(DiagnosingMessageDigestDecorator md, Object thing, FingerprintingConfig conf) {
        if (thing instanceof Node) {
            fingerprintNode(md, (Node) thing, conf);
        } else if (thing instanceof Relationship) {
            fingerprintRelationship(md, (Relationship) thing, conf);
        } else if (thing instanceof Path) {
            fingerprintPath(md, (Path) thing, conf);
        } else if (thing instanceof Map) {
            fingerprintMap(md, conf, (Map<String, Object>) thing);
        } else if (thing instanceof List) {
            fingerprintList(md, conf, (List) thing);
        } else {
            md.update(convertValueToString(thing).getBytes());
        }
    }

    private void fingerprintList(DiagnosingMessageDigestDecorator md, FingerprintingConfig conf, List list) {
        list.stream().forEach(o -> fingerprint(md, o, conf));
    }

    private void fingerprintPath(DiagnosingMessageDigestDecorator md, Path thing, FingerprintingConfig conf) {
        StreamSupport.stream(thing.nodes().spliterator(), false).forEach(o -> fingerprint(md, o, conf));
        StreamSupport.stream(thing.relationships().spliterator(), false).forEach(o -> fingerprint(md, o, conf));
    }

    private void fingerprintMap(
            DiagnosingMessageDigestDecorator md, FingerprintingConfig conf, Map<String, Object> map) {
        map.entrySet().stream()
                .filter(e -> {
                    if (!conf.getMapAllowList().isEmpty()) {
                        return conf.getMapAllowList().contains(e.getKey());
                    } else {
                        return !conf.getMapDisallowList().contains(e.getKey());
                    }
                })
                .sorted(Map.Entry.comparingByKey())
                .forEachOrdered(entry -> {
                    md.update(entry.getKey().getBytes());
                    md.update(fingerprint(entry.getValue(), conf).getBytes());
                });
    }

    @UserFunction("apoc.hashing.fingerprintGraph")
    @Description("""
            Calculates a MD5 checksum over the full graph.
            This function uses in-memory data structures.
            Unsuitable for cryptographic use-cases.""")
    public String fingerprintGraph(
            @Name(
                            value = "propertyExcludes",
                            defaultValue = "[]",
                            description = "Property keys to exclude from the hashing.")
                    List<String> excludedPropertyKeys) {
        FingerprintingConfig config = new FingerprintingConfig(Util.map(
                "allNodesDisallowList",
                excludedPropertyKeys,
                "allRelsDisallowList",
                excludedPropertyKeys,
                "mapDisallowList",
                excludedPropertyKeys,
                "strategy",
                FingerprintingConfig.FingerprintStrategy.EAGER.toString()));
        return withMessageDigest(config, messageDigest -> {
            Map<Long, String> colours = new HashMap<>();
            try (ResourceIterable<Node> allNodes = tx.getAllNodes()) {
                allNodes.forEach(node -> colours.put(node.getId(), fingerprint(node, config)));
            }

            // Relationship hashes are independent of node ids, so compute them once.
            List<HashedRelationship> relationships = new ArrayList<>();
            try (ResourceIterable<Relationship> allRels = tx.getAllRelationships()) {
                allRels.forEach(rel -> relationships.add(
                        new HashedRelationship(rel.getStartNodeId(), rel.getEndNodeId(), fingerprint(rel, config))));
            }

            // Colour refinement: a node's colour is repeatedly combined with the sorted colours of its
            // neighbours, so it ends up describing its position in the graph without relying on internal ids.
            MessageDigest roundDigest = newDigest(config);
            int distinct = new HashSet<>(colours.values()).size();
            for (int round = 0; round < colours.size(); round++) {
                Map<Long, List<String>> neighbourhoods = new HashMap<>();
                for (HashedRelationship rel : relationships) {
                    neighbourhoods
                            .computeIfAbsent(rel.startId(), k -> new ArrayList<>())
                            .add("OUT:" + rel.hash() + ":" + colours.get(rel.endId()));
                    neighbourhoods
                            .computeIfAbsent(rel.endId(), k -> new ArrayList<>())
                            .add("IN:" + rel.hash() + ":" + colours.get(rel.startId()));
                }
                Map<Long, String> refined = new HashMap<>();
                colours.forEach((id, colour) -> {
                    List<String> neighbourhood =
                            new ArrayList<>(neighbourhoods.getOrDefault(id, Collections.emptyList()));
                    Collections.sort(neighbourhood);
                    refined.put(id, hashOf(roundDigest, colour, neighbourhood));
                });
                colours.putAll(refined);

                int refinedDistinct = new HashSet<>(colours.values()).size();
                if (refinedDistinct == distinct) {
                    break;
                }
                distinct = refinedDistinct;
            }

            colours.values().stream().sorted().forEach(colour -> messageDigest.update(colour.getBytes()));
        });
    }

    private record HashedRelationship(long startId, long endId, String hash) {}

    private static MessageDigest newDigest(FingerprintingConfig config) {
        try {
            return MessageDigest.getInstance(config.getDigestAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private String hashOf(MessageDigest md, String colour, List<String> neighbourhood) {
        md.update(colour.getBytes());
        neighbourhood.forEach(entry -> {
            md.update((byte) '|');
            md.update(entry.getBytes());
        });
        return renderAsHex(md.digest());
    }

    private void fingerprintNode(DiagnosingMessageDigestDecorator md, Node node, FingerprintingConfig config) {
        switch (config.getStrategy()) {
            case EAGER:
                StreamSupport.stream(node.getLabels().spliterator(), false)
                        .map(Label::name)
                        .sorted()
                        .map(String::getBytes)
                        .forEach(md::update);
                break;
            case LAZY:
                StreamSupport.stream(node.getLabels().spliterator(), false)
                        .map(Label::name)
                        .filter(name -> config.getAllLabels().contains(name))
                        .sorted()
                        .map(String::getBytes)
                        .forEach(md::update);
        }

        final List<String> keysToRetain = new ArrayList<>(config.getAllNodesAllowList());
        keysToRetain.addAll(StreamSupport.stream(node.getLabels().spliterator(), false)
                .map(Label::name)
                .flatMap(label -> config.getNodeAllowMap().getOrDefault(label, Collections.emptyList()).stream())
                .collect(Collectors.toSet()));

        final List<String> keysToRemove = new ArrayList<>(config.getAllNodesDisallowList());
        keysToRemove.addAll(StreamSupport.stream(node.getLabels().spliterator(), false)
                .map(Label::name)
                .flatMap(label -> config.getNodeDisallowMap().getOrDefault(label, Collections.emptyList()).stream())
                .collect(Collectors.toSet()));
        keysToRemove.addAll(config.getMapDisallowList()); // just to backwards compatibility remove it

        final Map<String, Object> allProperties = getEntityProperties(node, config, keysToRetain, keysToRemove);
        fingerprint(md, allProperties, config);
    }

    private void fingerprintRelationship(
            DiagnosingMessageDigestDecorator md, Relationship rel, FingerprintingConfig config) {
        switch (config.getStrategy()) {
            case EAGER:
                md.update(rel.getType().name().getBytes());
                md.update(fingerprint(rel.getStartNode(), config).getBytes());
                md.update(fingerprint(rel.getEndNode(), config).getBytes());
                break;
            case LAZY:
                if (config.getAllTypes().contains(rel.getType().name())) {
                    md.update(rel.getType().name().getBytes());
                    md.update(fingerprint(rel.getStartNode(), config).getBytes());
                    md.update(fingerprint(rel.getEndNode(), config).getBytes());
                }
        }

        final List<String> keysToRetain = new ArrayList<>(config.getAllRelsAllowList());
        keysToRetain.addAll(config.getRelAllowMap().getOrDefault(rel.getType().name(), Collections.emptyList()));

        final List<String> keysToRemove = new ArrayList<>(config.getAllRelsDisallowList());
        keysToRemove.addAll(
                config.getRelDisallowMap().getOrDefault(rel.getType().name(), Collections.emptyList()));
        keysToRemove.addAll(config.getMapDisallowList()); // just to backwards compatibility remove it

        final Map<String, Object> allProperties = getEntityProperties(rel, config, keysToRetain, keysToRemove);
        fingerprint(md, allProperties, config);
    }

    private Map<String, Object> getEntityProperties(
            Entity entity, FingerprintingConfig config, List<String> keysToRetain, List<String> keysToRemove) {
        final Map<String, Object> allProperties;
        if (keysToRetain.isEmpty() && keysToRemove.isEmpty()) {
            switch (config.getStrategy()) {
                case LAZY:
                    allProperties = Collections.emptyMap();
                    break;
                default:
                    allProperties = entity.getAllProperties();
            }
        } else {
            allProperties = entity.getAllProperties();
            if (!keysToRetain.isEmpty()) {
                allProperties.keySet().retainAll(keysToRetain);
            }
            if (!keysToRemove.isEmpty()) {
                allProperties.keySet().removeAll(keysToRemove);
            }
        }
        return allProperties;
    }

    private String withMessageDigest(FingerprintingConfig conf, Consumer<DiagnosingMessageDigestDecorator> consumer) {
        try {
            MessageDigest md = MessageDigest.getInstance(conf.getDigestAlgorithm());
            DiagnosingMessageDigestDecorator dmd = new DiagnosingMessageDigestDecorator(md);
            consumer.accept(dmd);
            return renderAsHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String renderAsHex(byte[] content) {
        Formatter formatter = new Formatter();
        for (byte b : content) {
            formatter.format("%02X", b);
        }
        return formatter.toString();
    }

    private String convertValueToString(Object value) {
        if (value == null) {
            return "";
        }
        if (value.getClass().isArray()) {
            return nativeArrayToString(value);
        } else {
            return value.toString();
        }
    }

    private String nativeArrayToString(Object value) {
        StringBuilder sb = new StringBuilder();
        if (value instanceof String[]) {
            for (String s : (String[]) value) {
                sb.append(s);
            }
        } else if (value instanceof double[]) {
            for (double d : (double[]) value) {
                sb.append(d);
            }
        } else if (value instanceof long[]) {
            for (long l : (long[]) value) {
                sb.append(l);
            }
        } else if (value instanceof byte[]) {
            for (byte l : (byte[]) value) {
                sb.append(l);
            }
        } else {
            throw new UnsupportedOperationException(
                    "cannot yet deal with " + value.getClass().getName());
        }
        return sb.toString();
    }

    /**
     * if debug log level is enabled, send all updates to the message digest to the log as well for diagnosis
     */
    private class DiagnosingMessageDigestDecorator {
        private final MessageDigest delegate;

        public DiagnosingMessageDigestDecorator(MessageDigest delegate) {
            this.delegate = delegate;
        }

        public void update(byte[] value) {
            if (log.isDebugEnabled()) {
                log.debug("adding to message digest {}", new String(value));
            }
            delegate.update(value);
        }
    }
}
