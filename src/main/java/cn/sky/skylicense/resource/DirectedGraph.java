package cn.sky.skylicense.resource;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

/** Deterministic O(V + E) dependency ordering with cycle-tolerant fallback. */
public final class DirectedGraph {
    private final Map<String, Vertex> vertices = new LinkedHashMap<>();

    public void putNode(String name) {
        vertices.computeIfAbsent(name, Vertex::new);
    }

    /** Records that {@code sourceName} depends on {@code dependencyName}. */
    public void addEdge(String sourceName, String dependencyName) {
        Vertex source = vertices.computeIfAbsent(sourceName, Vertex::new);
        Vertex dependency = vertices.computeIfAbsent(dependencyName, Vertex::new);
        if (dependency.dependents.add(source)) {
            source.inDegree++;
        }
    }

    public List<String> topoSort() {
        Map<Vertex, Integer> remainingDegrees = new LinkedHashMap<>();
        Queue<Vertex> ready = new ArrayDeque<>();
        for (Vertex vertex : vertices.values()) {
            remainingDegrees.put(vertex, vertex.inDegree);
            if (vertex.inDegree == 0) {
                ready.add(vertex);
            }
        }

        List<String> result = new ArrayList<>(vertices.size());
        while (!ready.isEmpty()) {
            Vertex dependency = ready.remove();
            result.add(dependency.className);
            for (Vertex dependent : dependency.dependents) {
                int remaining = remainingDegrees.computeIfPresent(
                        dependent, (ignored, value) -> value - 1);
                if (remaining == 0) {
                    ready.add(dependent);
                }
            }
        }

        if (result.size() != vertices.size()) {
            Set<String> ordered = new LinkedHashSet<>(result);
            for (Vertex vertex : vertices.values()) {
                if (ordered.add(vertex.className)) {
                    result.add(vertex.className);
                }
            }
        }
        return result;
    }

    private static final class Vertex {
        private final String className;
        private final Set<Vertex> dependents = new LinkedHashSet<>();
        private int inDegree;

        private Vertex(String className) {
            this.className = className;
        }
    }
}
