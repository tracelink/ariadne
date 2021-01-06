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
package com.tracelink.appsec.ariadne.write;

import com.opencsv.CSVWriter;
import com.tracelink.appsec.ariadne.model.Artifact;
import com.tracelink.appsec.ariadne.model.InternalArtifact;
import com.tracelink.appsec.ariadne.utils.Utils;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of a {@link Writer} that writes output to CSV files.
 *
 * @author mcool
 */
public class StandardCsvWriter implements Writer {

	private static final Logger LOG = LoggerFactory.getLogger(StandardCsvWriter.class);
	private final String outputPath;
	private List<Artifact> artifacts;

	public StandardCsvWriter(String path) {
		File outputDir = new File(path);
		boolean success = outputDir.mkdirs();
		if (!success && !outputDir.isDirectory()) {
			throw new IllegalArgumentException(
					"Please provide a valid path to the output directory");
		}
		outputPath = path;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setArtifacts(List<Artifact> artifacts) {
		this.artifacts = artifacts;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeDependencies() {
		String fileName = outputPath + "/dependencies.csv";
		try (CSVWriter writer = new CSVWriter(new FileWriter(fileName))) {
			writer.writeNext(new String[]{"Project Name", "# Used", "# Versions"});

			artifacts.stream().filter(InternalArtifact.class::isInstance).forEach(a -> writer
					.writeNext(new String[]{a.getName(), String.valueOf(a.getConnections()),
							String.valueOf(a.getVersions().size())}));
		} catch (IOException e) {
			LOG.error("Exception occurred while writing dependency summary: {}", e.getMessage());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeVulnerabilities() {
		String fileName = outputPath + "/vulnerabilities.csv";
		try (CSVWriter writer = new CSVWriter(new FileWriter(fileName))) {

			int totalArtifacts = 0;
			int totalFindings = 0;

			Map<String, List<Artifact>> artifactMap = new TreeMap<>();

			for (Artifact artifact : artifacts) {
				if (artifact.isVulnerable()) {
					String artifactName = Utils.getArtifactName(artifact.getName());
					if (artifactMap.containsKey(artifactName)) {
						artifactMap.get(artifactName).add(artifact);

					} else {
						List<Artifact> groupedArtifacts = new ArrayList<>();
						groupedArtifacts.add(artifact);
						artifactMap.put(artifactName, groupedArtifacts);
						totalArtifacts += 1;
					}
					totalFindings += artifact.getFindings();
				}
			}

			LOG.info("Vulnerable OSS Libraries: {}", totalArtifacts);

			for (Entry<String, List<Artifact>> artifactNameEntry : artifactMap.entrySet()) {
				String artifactName = artifactNameEntry.getKey();
				List<Artifact> groupedArtifacts = artifactNameEntry.getValue();
				writer.writeNext(new String[]{"", ""});
				String displayName = Utils.getDisplayName(artifactName);
				writer.writeNext(new String[]{displayName, "Total"});
				groupedArtifacts.forEach(a -> writer
						.writeNext(new String[]{a.getName(), String.valueOf(a.getFindings())}));
				int numFindings = groupedArtifacts.stream().mapToInt(Artifact::getFindings).sum();
				double percent = ((numFindings * 1.00) / totalFindings) * 100;
				writer.writeNext(new String[]{String.format("%.2f%%", percent),
						String.valueOf(numFindings)});
			}
		} catch (IOException e) {
			LOG.error("Exception occurred while writing vulnerability summary: {}", e.getMessage());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void writeTiers() {
		String fileName = outputPath + "/tiers.csv";
		try (CSVWriter writer = new CSVWriter(new FileWriter(fileName))) {
			writer.writeNext(new String[]{
					"Project Name",
					"Tier",
					"Internal Dependencies to Upgrade",
					"External Dependencies to Upgrade"
			});

			int numArtifacts = 0;
			int numTiers = 0;

			for (Artifact artifact : artifacts) {
				if (artifact.getTier() != -1) {
					numArtifacts += 1;
					numTiers = Integer.max(numTiers, artifact.getTier() + 1);
					writer.writeNext(new String[]{
							artifact.getName(),
							String.valueOf(artifact.getTier()),
							formatInternalUpgrades(artifact.getInternalUpgrades()),
							formatExternalUpgrades(artifact.getExternalUpgrades())
					});
				}
			}

			LOG.info("Artifacts to Update: {}", numArtifacts);
			LOG.info("Number of Tiers: {}", numTiers);
		} catch (IOException e) {
			LOG.error("Exception occurred while writing tier summary: {}", e.getMessage());
		}
	}

	/**
	 * Format the output for an internal upgrades list.
	 *
	 * @param internalUpgrades list of internal artifacts to upgrade
	 * @return string containing all internal upgrades
	 */
	private String formatInternalUpgrades(Set<String> internalUpgrades) {
		if (internalUpgrades.isEmpty()) {
			return "None";
		}
		StringBuilder sb = new StringBuilder();
		internalUpgrades.forEach(upgrade -> {
			sb.append(upgrade);
			sb.append("\n");
		});
		return sb.toString().trim();
	}

	/**
	 * Format the output for an external upgrades map.
	 *
	 * @param externalUpgrades map of external artifacts to upgrade
	 * @return string containing all external upgrades
	 */
	private String formatExternalUpgrades(Map<String, Set<String>> externalUpgrades) {
		if (externalUpgrades.isEmpty()) {
			return "None";
		}
		StringBuilder sb = new StringBuilder();
		for (Entry<String, Set<String>> directUpgradeEntry : externalUpgrades.entrySet()) {
			String directUpgrade = directUpgradeEntry.getKey();
			Set<String> transitiveUpgrades = directUpgradeEntry.getValue();
			if (transitiveUpgrades.size() == 1 && transitiveUpgrades.contains(directUpgrade)) {
				sb.append(directUpgrade);
				sb.append("\n");
			} else {
				sb.append(directUpgrade);
				sb.append(" (");
				transitiveUpgrades.forEach(u -> {
					sb.append(u);
					sb.append(", ");
				});
				sb.delete(sb.length() - 2, sb.length());
				sb.append(")\n");
			}
		}
		return sb.toString().trim();
	}
}
