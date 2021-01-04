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
package com.tracelink.appsec.ariadne.model;

import com.tracelink.appsec.ariadne.utils.Utils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.IntStream;

/**
 * Represents an internal, or in-house artifact. Contains multiple versions and can be assigned to
 * a tier.
 *
 * @author mcool
 */
public class InternalArtifact implements Artifact {

	private final String artifactName;
	private final TreeSet<InternalVersion> versions = new TreeSet<>();
	private final Set<String> internalUpgrades = new TreeSet<>();
	private final Map<String, Set<String>> externalUpgrades = new TreeMap<>();
	private final Set<String> cycles = new HashSet<>();
	private int tier = -1;

	public InternalArtifact(String artifact) {
		this.artifactName = Utils.getArtifactName(artifact);
		versions.add(new InternalVersion(Utils.getVersion(artifact)));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return artifactName;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getTier() {
		return tier;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getConnections() {
		return versions.stream().mapToInt(InternalVersion::getConnections).sum();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getFindings() {
		throw new UnsupportedOperationException("Cannot get findings for an internal artifact");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Set<String> getVersions() {
		Set<String> versionNumbers = new TreeSet<>();
		versions.forEach(v -> versionNumbers.add(v.getVersion()));
		return versionNumbers;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isVulnerable() {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addFindings(int findings) {
		throw new UnsupportedOperationException("Cannot add findings to an internal artifact");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addVersion(String version) {
		for (InternalVersion v : versions) {
			// If the given version exists, do nothing
			if (v.getVersion().equals(version)) {
				return;
			}
		}
		// If the given version does not exist, add it
		versions.add(new InternalVersion(version));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addParent(String version, Artifact parent) {
		for (InternalVersion v : versions) {
			// If the given version exists, add parent to that version
			if (v.getVersion().equals(version)) {
				v.addParent(parent);
				return;
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addChild(String version, Artifact child) {
		for (InternalVersion v : versions) {
			// If the given version exists, add parent to that version
			if (v.getVersion().equals(version)) {
				v.addChild(child);
				return;
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void findCycles(List<String> visited) {
		if (visited.size() == 0 || versions.first().hasChild(visited.get(visited.size() - 1))) {
			if (visited.contains(artifactName)) {
				int index = visited.indexOf(artifactName);
				IntStream.range(index + 1, visited.size()).forEach(i -> cycles.add(visited.get(i)));
				return;
			}

			List<String> visitedCopy = new ArrayList<>(visited);
			visitedCopy.add(artifactName);
			List<Artifact> updated = new ArrayList<>();
			versions.forEach(v -> v.findCycles(visitedCopy, updated));
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void assignTiers() {
		throw new UnsupportedOperationException(
				"Cannot start assigning tiers from an internal artifact");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void assignTier(int tier, String root, String child, List<String> visited) {
		// Only do something if the child is a child of the most recent version of this artifact
		if (versions.first().hasChild(child)) {
			// Add vulnerability to the correct list of upgrades
			if (tier == 0) {
				if (externalUpgrades.containsKey(child)) {
					externalUpgrades.get(child).add(root);
				} else {
					Set<String> upgradeSet = new TreeSet<>();
					upgradeSet.add(root);
					externalUpgrades.put(child, upgradeSet);
				}
			} else {
				internalUpgrades.add(child);
			}

			// Prevent infinite looping
			if (visited.contains(artifactName)) {
				return;
			}

			// Update tier, if the tier of this artifact is less than the given one
			if (this.tier < tier) {
				this.tier = tier;
			}
			List<String> visitedCopy = new ArrayList<>(visited);
			visitedCopy.add(artifactName);
			List<Artifact> updated = new ArrayList<>();
			versions.forEach(v -> v.assignTier(tier,
					root, artifactName, visitedCopy, updated, cycles));
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Set<String> getInternalUpgrades() {
		return Collections.unmodifiableSet(internalUpgrades);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Set<String>> getExternalUpgrades() {
		return Collections.unmodifiableMap(externalUpgrades);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int compareTo(Artifact o) {
		return artifactName.compareTo(o.getName());
	}
}
