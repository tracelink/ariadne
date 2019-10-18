# Ariadne #

Generates a tiered upgrade path to help resolve vulnerable open source libraries using a bottom-up 
approach.

## Overview ##

Upgrading vulnerable open source libraries is a repetitive and inefficient task. Using a source composition analysis 
tool is useful to identify vulnerable libraries where they exist in code, but it does not provide a clear path to 
perform individual upgrades. 

Typically, upgrades are performed ad-hoc from the top-down, removing all instances of vulnerable open source libraries
from a single application before moving on. In practice, this creates problems when projects depend on other internal 
code. It is not uncommon to find that a direct dependency of a project is itself an internal project. Furthermore, this 
internal dependency may have its own vulnerable open source libraries that need to be upgraded. To address this issue,
developers are forced to context switch, remove vulnerable libraries from the internal dependency, and then return to 
the original project to update the version of that dependency. 

In security, we want to be force multipliers and avoid this context switching. So instead we suggest using a bottom-up approach, which 
guarantees that all internal dependencies of a project will be upgraded before work begins. This enables developers to 
perform all upgrades for a project at once, including testing and bug fixes, without having to return later to address 
additional issues.

In order to accomplish this, however, we need to understand the relationships between our projects. Without this, we 
would have no idea where to start or what order to perform upgrades. In short, we need a clear upgrade path, including 
starting points, ending points and every step in between. Considering the scale and complexity of these relationships 
(think microservices), it is evident that automation is needed to do this well. 

Enter Ariadne.

### Understanding the Upgrade Path ###

The main purpose of Ariadne is to produce an explicit path to perform upgrades. Ariadne defines this path using 
tiers.

A **tier** is a nonempty set of internal projects that need open source library upgrades. Ariadne's algorithm 
guarantees that all of the projects in a single tier do not have dependencies upon each other. This simply means that 
vulnerable library upgrades can be performed on all of these projects *simultaneously*, without running into the 
scenario described in the Overview section. 

Tiers are additionally *ranked*, indicating the order in which upgrades should be performed. The upgrade path simply 
becomes the tier order, with the result that upgrades are effectively performed in sections, tier-by-tier. Again, the 
order of upgrades within each tier is *arbitrary*, so multiple projects can be updated by developers at the same time.

Tiers start at zero and count upward. Following the upgrade path is as simple as performing all upgrades for Tier 0, 
then all the upgrades for Tier 1, and so on.

### Generating the Upgrade Path ###

In order to generate the upgrade path, Ariadne requires two general inputs:

1. A list of direct dependency relationships between internal projects and external, open source libraries (or any 
combination of those two types).
2. A list of vulnerable, open source libraries.

Given that there are many different dependency frameworks and SCA tools, Ariadne is abstracted to expect only these 
general inputs, and provides interfaces to implement in order to extend its existing functionality. There are currently 
implementations to work with the following frameworks and tools:

**Dependency Frameworks**
1. Maven
2. Pom Explorer

**Source Composition Analysis Tools**
1. Sonatype Nexus IQ


Ariadne has a command line interface that allows you to specify which parsers you would like to use with the data you
provide. You are also welcome to create a custom parser for your dependency or vulnerable library data by implementing
the relevant interfaces.

### Walkthrough ###

For this example, we are going to use Maven as our dependency framework and Sonatype as our SCA tool. First we gather 
our two sets of data for Ariadne. 

For our dependencies, we will generate Maven dependency trees for all of the source code we wish to analyze. Dependency 
trees should be generated using the `mvn dependency:tree` command, and an output file should be specified using the 
`-DoutputFile={/path/to/file}` option. This option will print the dependency tree cleanly to the file without all of the
informational messages typically printed to the console. See the Helpers section for a script that will automate 
generation of the dependency trees. Once generated, all of the dependency tree files should be placed in a single 
directory. The path to the directory will serve as input to Ariadne. If you only want to analyze a single file, you 
can provide Ariadne with the path to the file instead of a directory.

For our vulnerabilities, we will save some subset of violations identified by the Sonatype Nexus IQ tool. On the 
Dashboard page, use the filters on the left to select the violations you would like to resolve. Then click the 
"Export Violations Data" button on the upper right corner to download a CSV file with all of the vulnerability data. 
Store this file somewhere on your computer. You will provide Ariadne with the path to this file to load your 
vulnerabilities.

Once the data has been collected, you can run Ariadne using the following command:

    java -jar ariadne.jar -d mvn-tree {/path/to/dependencies} -v nexus-iq-vios {/path/to/vulnerabilities} -w csv {/path/to/output} -i {internal identifiers}
    
Breaking down the arguments in the command.

- `-d mvn-tree {/path/to/dependencies}` tells Ariadne to parse the dependencies found in the given directory using the 
Maven dependency tree implementation
- `-v nexus-iq-vios {/path/to/vulnerabilities}` tells Ariadne to parse the vulnerabilities found in the given file 
using the Nexus IQ violations implementation
- `-w csv {/path/to/output}` tells Ariadne to write output to the given directory in CSV format
- `-i {internal identifiers}` tells Ariadne to treat any projects containing the strings provided here as source code

The last section, containing the internal identifiers, are used to distinguish between internal and external artifacts. 
For example, an internal identifier might be "com.example". You can provide as many internal identifiers as you want 
after the `-i` option, but you must include at least one.

Using these parameters, the script will output a file in the specified output directory called "tiers.csv", which
contains the complete upgrade path.

You can also use the `--stats` command line option to write some additional statistics to the specified output 
directory. 

### Using the Output ###

The CSV file that Ariadne outputs contains several columns of useful information, which are explained here in greater
detail.

- **Project Name:** The name of the project to be upgraded. For Maven projects, this is formatted as 
"groupId:artifactId:version".
- **Tier:** The tier to which this project has been assigned.
- **Internal Dependencies to Upgrade:** All internal dependencies of this project that need a version upgrade. This 
indicates that the internal dependency had upgrades performed in previous tiers. For all Tier 0 projects, there will be 
no internal dependencies to upgrade.
- **External Dependencies to Upgrade:** All vulnerable external dependencies of this project that need to be upgraded. 
In some scenarios, the direct external dependencies of a project are not vulnerable themselves, but may depend on a
vulnerable open source library. Where this occurs, the direct external dependency of the project will be listed first, 
with the root cause of the vulnerability listed in parentheses afterwards. For example, 
com.example:library-a:1.0.0 is vulnerable to org.example:library-b:1.0.0. A project depending on library-a would report 
the following in its external dependencies to upgrade: `com.example:library-a:1.0.0 (org.example:library-b:1.0.0)`, 
indicating library-b is the root vulnerability, but library-a is being directly depended on.

With this information, you simply perform all upgrades listed in the internal and external dependencies to upgrade 
columns, starting with the projects in Tier 0, and then working through each of the higher tiers. When finished, all 
projects are upgraded and all vulnerable open source libraries are removed.

## Helpers ##

