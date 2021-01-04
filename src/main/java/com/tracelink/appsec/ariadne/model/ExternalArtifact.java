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
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Represents an external, or third-party artifact. Contains only a single version and cannot be
 * assigned to a tier.
 *
 * @author mcool
 */
public class ExternalArtifact implements Artifact {

	private final String fullName;
	private final String version;
	private final Set<Artifact> parents = new TreeSet<>();
	private final Set<Artifact> children = new TreeSet<>();
	private int findings = 0;

	public ExternalArtifact(String artifact) {
		this.fullName = artifact;
		this.version = Utils.getVersion(artifact);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return fullName;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getTier() {
		return -1;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getConnections() {
		return parents.size();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getFindings() {
		return findings;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Set<String> getVersions() {
		return Collections.singleton(version);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isVulnerable() {
		return findings > 0;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addFindings(int findings) {
		this.findings += findings;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addVersion(String version) {
		throw new UnsupportedOperationException("Cannot add a version to an external artifact");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addParent(String version, Artifact parent) {
		if (this.version.equals(version)) {
			parents.add(parent);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addChild(String version, Artifact child) {
		if (this.version.equals(version)) {
			children.add(child);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void findCycles(List<String> visited) {
		throw new UnsupportedOperationException("Cannot find cycles for an external artifact");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void assignTiers() {
		assignTier(0, fullName, fullName, new ArrayList<>());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void assignTier(int tier, String root, String direct, List<String> visited) {
		if (visited.contains(fullName)) {
			return;
		}
		List<String> visitedCopy = new ArrayList<>(visited);
		visitedCopy.add(fullName);
		for (Artifact parent : parents) {
			parent.assignTier(tier, root, fullName, visitedCopy);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Set<String> getInternalUpgrades() {
		throw new UnsupportedOperationException(
				"Cannot get internal upgrades for an external artifact");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Map<String, Set<String>> getExternalUpgrades() {
		throw new UnsupportedOperationException(
				"Cannot get external upgrades for an external artifact");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int compareTo(Artifact o) {
		return fullName.compareTo(o.getName());
	}
}
