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

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Represents a software component, such as a Maven artifact or an NPM library. Stores information
 * about vulnerabilities and relationships to other artifacts.
 *
 * @author mcool
 */
public interface Artifact extends Comparable<Artifact> {

	/**
	 * Gets the name of this artifact.
	 *
	 * @return artifact name
	 */
	String getName();

	/**
	 * Gets the tier this artifact is assigned to. A tier represents a grouping of artifacts that
	 * are not dependent upon one another and can be upgraded simultaneously.
	 *
	 * @return artifact tier
	 */
	int getTier();

	/**
	 * Gets the number of other artifacts that this artifact is connected to.
	 *
	 * @return number of artifact connections
	 */
	int getConnections();

	/**
	 * Gets the number of vulnerability findings of this artifact.
	 *
	 * @return number of artifact findings
	 */
	int getFindings();

	/**
	 * Gets the list of known versions of this artifact.
	 *
	 * @return list of artifact versions
	 */
	Set<String> getVersions();

	/**
	 * Determines whether this artifact contains any vulnerabilities.
	 *
	 * @return true if this artifact is vulnerable, false otherwise
	 */
	boolean isVulnerable();

	/**
	 * Adds the given number of findings to this artifact's findings.
	 *
	 * @param findings number of findings to add
	 */
	void addFindings(int findings);

	/**
	 * Adds the given version string to this artifact's list of versions. If the given version is
	 * already present, does nothing.
	 *
	 * @param version version to add
	 */
	void addVersion(String version);

	/**
	 * Adds the given {@link Artifact} to the given version of this artifact as a parent. If this
	 * artifact does not contain the given version, does nothing.
	 *
	 * @param version version of the artifact to add the parent to
	 * @param parent  the parent artifact
	 */
	void addParent(String version, Artifact parent);

	/**
	 * Adds the given {@link Artifact} to the given version of this artifact as a child. If this
	 * artifact does not contain the given version, does nothing.
	 *
	 * @param version version of the artifact to add the child to
	 * @param child   the child artifact
	 */
	void addChild(String version, Artifact child);

	/**
	 * Identifies cycles among artifact dependencies using the given list of visited artifacts.
	 *
	 * @param visited list of artifacts that have already been visited while identifying cycles
	 */
	void findCycles(List<String> visited);

	/**
	 * Assigns a tier to all artifacts that depend on this artifact. A tier will only be assigned
	 * if an artifact is internal and if it contains vulnerable dependencies.
	 */
	void assignTiers();

	/**
	 * Recursively assigns a tier to this artifact and artifacts that depend upon it. A tier will
	 * only be assigned if an artifact is internal and if it contains vulnerable dependencies.
	 *
	 * @param tier    current tier
	 * @param root    root artifact of the vulnerability
	 * @param direct  direct vulnerable dependency of this artifact
	 * @param visited list of previously visited artifacts
	 */
	void assignTier(int tier, String root, String direct, List<String> visited);

	/**
	 * Gets the set of internal artifact upgrades for this artifact.
	 *
	 * @return set of internal artifact upgrades
	 */
	Set<String> getInternalUpgrades();

	/**
	 * Gets a map of external artifact upgrades for this artifact. Each entry contains the direct
	 * external artifact to upgrade and a set of its root vulnerable dependencies.
	 *
	 * @return map of external artifact upgrades
	 */
	Map<String, Set<String>> getExternalUpgrades();
}
