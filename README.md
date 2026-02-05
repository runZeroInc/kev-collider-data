# kev-collider-data

This is the data repository for [KEV Collider](https://www.runzero.com/kev-collider/), an interactive test bench for filtering, sorting, and prioritizing CISA KEV-listed vulnerabilities, as described in runZero's paper, [KEVology: an analysis of exploits, scores, and timelines on the CISA KEV](https://www.runzero.com/resources/kevology/). The report is a pretty fun read, and KEV Collider is pretty fun to use to replicate the findings in the report. Give it a whirl!

## Contributing, Issues, and Bugs

One of the upsides of publishing the backing data is that we can collect complaints, and more importantly, feature requests, for the front end at [KEV Collider](https://www.runzero.com/kev-collider/). Of course, you could just write your own visualization, filtering, and sorting (thanks to runZero's permissive [LICENSE](LICENSE)) for this data, but it seems like it's a lot easier to bully us into implementing your ideas.

So, if you happen to come across a solid, public data set that talks about CVE-identified vulnerabilities, and want to see it integrated, open a GitHub issue in the usual way.

One exception is if you happen across a security issue with either this repo, or with the web front end. For security vulnerability reporting, please refer to runZero's security.txt guidance, at https://runzero.com/.well-known/security.txt. And thanks for your report. We'll be suitably impressed with your finding.

## Usage: This repo

This repo is pretty straight forward. You'll find a whole pile of JSON files in `json/`, each of which describes a KEV-listed CVE with a bunch of decorations. To make sense of those JSON files, check it against the [current schema](schema-v1.0.0-dev.json). These JSON files are updated periodically as new information is released; new KEVs, new Nuclei templates, that sort of thing.

There's also a [Jupyter Notebook](kev-explore.ipynb) that steps through most of the findings detailed in the paper, but with fresh data (so you won't get exactly the same ratios as documented, but time and exploitation marches on).

## Usage: KEV Collider

The power of KEV Collider becomes pretty apparent when using the built in filtering and sorting. Because it's a static website, there is no notion of sessions or cookies or anything like that, which means all the filtering ends up as GET request parameters. For example, for "Straight-Shot RCE" is really just:

```
https://www.runzero.com/kev-collider/?cvss.av=network&cvss.pr=none&cvss.ui=none&cvss.i=high
```

(aka, the CVSSv3.1 vectors of Access Vector: **Network**, Privileges Required: **None**, User Interaction: **None**, Integrity Impact: **High**). This means you can save these filters as bookmarks, pass them around with friends, fiddle with them offline, and other uses we haven't thought of yet.

If you come up with a particularly useful set of filters in your experimentation, let us know as a feature request, and we'll consider adding it as a preset filter!

## About runZero

runZero is an exposure management platform providing unrivaled visibility across your entire internal and external attack surface — covering IT, OT, IoT, mobile, and cloud. Uncover the unknowns, reveal elusive exposures, and target the true risks other tools miss. Give it a [try for free](https://runzero.com/try)!
