/*
Copyright 2019 TraceLink, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.tracelink.appsec.ariadne.analyze;

import com.tracelink.appsec.ariadne.model.Artifact;
import com.tracelink.appsec.ariadne.model.ExternalArtifact;
import com.tracelink.appsec.ariadne.model.InternalArtifact;
import com.tracelink.appsec.ariadne.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class Analyzer {
    private List<String> internalIdentifiers;
    private Map<String, Artifact> artifacts = new TreeMap<>();

    public Analyzer(List<String> internalIdentifiers) {
        this.internalIdentifiers = internalIdentifiers;
    }

    public List<Artifact> getArtifacts() {
        return Collections.unmodifiableList(new ArrayList<>(artifacts.values()));
    }

    public void analyzeDependencies(List<Map.Entry<String, String>> dependencies) {
        for (Map.Entry<String, String> dependency : dependencies) {
            // Get parent and child names
            String parent = dependency.getKey();
            String child = dependency.getValue();
            // Get parent and child artifacts
            Artifact parentArtifact = getArtifactForName(parent);
            Artifact childArtifact = getArtifactForName(child);
            // Add parent artifact to child artifact and vice versa
            childArtifact.addParent(Utils.getVersion(child), parentArtifact);
            parentArtifact.addChild(Utils.getVersion(parent), childArtifact);
        }
    }

    public void analyzeVulnerabilities(List<Map.Entry<String, Integer>> vulnerabilities) {
        for (Map.Entry<String, Integer> vulnerability : vulnerabilities) {
            String fullName = vulnerability.getKey();
            Integer findings = vulnerability.getValue();

            Artifact artifact = getArtifactForName(fullName);
            if (artifact.getConnections() == 0) {
                System.out.println(String.format("WARNING: Vulnerability not found: %s", artifact.getName()));
            }
            artifact.addFindings(findings);
        }
    }

    private Artifact getArtifactForName(String fullName) {
        // Parse useful data from dependency full name
        String artifactName = Utils.getArtifactName(fullName);
        String version = Utils.getVersion(fullName);

        Artifact artifact;
        if (artifacts.containsKey(fullName)) {
            // We have already stored this external artifact
            artifact = artifacts.get(fullName);
        } else if (artifacts.containsKey(artifactName)) {
            // We have already stored this internal artifact
            artifact = artifacts.get(artifactName);
            artifact.addVersion(version);
        } else if (internalIdentifiers.stream().anyMatch(artifactName::contains)) {
            // New internal artifact
            artifact = new InternalArtifact(fullName);
            artifacts.put(artifactName, artifact);
        } else {
            // New external artifact
            artifact = new ExternalArtifact(fullName);
            artifacts.put(fullName, artifact);
        }
        return artifact;
    }

    public void analyzeTiers() {
        // Identify cycles to prevent addition of extra tiers
        for (Artifact artifact : artifacts.values()) {
            if (artifact instanceof InternalArtifact) {
                artifact.findCycles(new ArrayList<>());
            }
        }
        // Assign tiers to internal artifacts affected by vulnerable external artifacts
        for (Artifact artifact : artifacts.values()) {
            if (artifact.isVulnerable()) {
                artifact.assignTiers();
            }
        }
    }
}
