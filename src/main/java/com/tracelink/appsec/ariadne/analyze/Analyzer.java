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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Analyzes dependencies and vulnerabilities of projects to construct a full dependency graph,
 * with external dependencies marked as vulnerable where appropriate. Analyzes the complete graph to
 * assign each internal project to a tier.
 *
 * @author mcool
 */
public class Analyzer {

	private static final Logger LOG = LoggerFactory.getLogger(Analyzer.class);
	private final List<String> internalIdentifiers;
	private final Map<String, Artifact> artifacts = new TreeMap<>();

	public Analyzer(List<String> internalIdentifiers) {
		this.internalIdentifiers = internalIdentifiers;
	}

	/**
	 * Gets all artifacts stored in this analyzer.
	 *
	 * @return unmodifiable list of artifacts
	 */
	public List<Artifact> getArtifacts() {
		return Collections.unmodifiableList(new ArrayList<>(artifacts.values()));
	}

	/**
	 * Analyzes the given list of dependency entries to construct a graph of artifact dependencies.
	 * Each entry in the list is composed of two strings: the first is the parent artifact name and
	 * the second is the child artifact name. An {@link Artifact} is constructed for each string and
	 * the unique artifacts are stored in the local {@code artifacts} map.
	 *
	 * @param dependencies list of dependency entries that are used to construct the dependency
	 *                     graph
	 */
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

	/**
	 * Analyzes the list of vulnerability entries to mark artifacts stored in the local {@code
	 * artifacts} map as vulnerable. Each entry in the list is composed of a string and an integer:
	 * the string is the name of a vulnerable artifact and the integer represents the number of
	 * vulnerabilities associated with that artifact.
	 *
	 * @param vulnerabilities list of vulnerability entries that are used to mark artifacts in the
	 *                        dependency graph as vulnerable
	 */
	public void analyzeVulnerabilities(List<Map.Entry<String, Integer>> vulnerabilities) {
		for (Map.Entry<String, Integer> vulnerability : vulnerabilities) {
			String fullName = vulnerability.getKey();
			Integer findings = vulnerability.getValue();

			Artifact artifact = getArtifactForName(fullName);
			// If artifact is not connected to any other node in the dependency graph, log warning
			if (artifact.getConnections() == 0) {
				LOG.warn("Vulnerability not found: {}", artifact.getName());
			}
			// Add findings for this artifact
			artifact.addFindings(findings);
		}
	}

	/**
	 * Gets the artifact from the local {@code artifacts} map with the given name, if it exists.
	 * Otherwise, creates a new artifact and stores it in the local {@code artifacts} map, before
	 * returning the artifact.
	 *
	 * @param fullName full name of the artifact to retrieve
	 * @return an artifact with the given name
	 */
	private Artifact getArtifactForName(String fullName) {
		// Parse useful data from dependency full name
		String artifactName = Utils.getArtifactName(fullName);
		String version = Utils.getVersion(fullName);

		Artifact artifact;
		if (artifacts.containsKey(fullName)) {
			// If the artifacts map contains the full name, we have already stored this external
			// artifact
			artifact = artifacts.get(fullName);
		} else if (artifacts.containsKey(artifactName)) {
			// If the artifacts map contains the artifact name, we have already stored this internal
			// artifact
			artifact = artifacts.get(artifactName);
			artifact.addVersion(version);
		} else if (internalIdentifiers.stream().anyMatch(artifactName::contains)) {
			// If any of the internal identifiers is contained in the artifact name, this is a new
			// internal artifact
			artifact = new InternalArtifact(fullName);
			artifacts.put(artifactName, artifact);
		} else {
			// If none of the internal identifiers is contained in the artifact name, this is a new
			// external artifact
			artifact = new ExternalArtifact(fullName);
			artifacts.put(fullName, artifact);
		}
		return artifact;
	}

	/**
	 * Analyzes the dependency graph to assign each internal artifact to a tier. Ensures that if
	 * cycles exist in the dependency graph, they are handled correctly to prevent unnecessary
	 * addition of tiers.
	 */
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
