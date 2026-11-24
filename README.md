# kev-collider-data

This is the data repository for [KEV Collider](https://www.runzero.com/kev-collider/), an interactive test bench for filtering, sorting, and prioritizing CISA KEV-listed vulnerabilities, as described in runZero's paper, [KEVology: an analysis of exploits, scores, and timelines on the CISA KEV](https://www.runzero.com/resources/kevology/). The report is a pretty fun read, and KEV Collider is pretty fun to use to replicate the findings in the report. Give it a whirl!

## Contributing, Issues, and Bugs

One of the upsides of publishing the backing data is that we can collect complaints, and more importantly, feature requests, for the front end at [KEV Collider](https://www.runzero.com/kev-collider/). Of course, you could just write your own visualization, filtering, and sorting (thanks to runZero's permissive [LICENSE](LICENSE)) for this data, but it seems like it's a lot easier to bully us into implementing your ideas.

So, if you happen to come across a solid, public data set that talks about CVE-identified vulnerabilities, and want to see it integrated, open a GitHub issue in the usual way. Public, actively maintained data sources that can be consumed as Git submodules are especially useful here; source repositories live under `sources/`, while generated KEV context records live under `json/`.

Pull requests are welcome for pipeline fixes, validation improvements, schema improvements, and source integrations. If you want to propose a new source, please include what CVE-keyed signal it adds, where it should live under `sources/`, how often it updates, and any licensing or attribution requirements we should preserve.

One exception is if you happen across a security issue with either this repo, or with the web front end. For security vulnerability reporting, please refer to runZero's security.txt guidance, at https://runzero.com/.well-known/security.txt. And thanks for your report. We'll be suitably impressed with your finding.

## Usage: This repo

This repo is pretty straight forward. You'll find a whole pile of JSON files in `json/`, each of which describes a KEV-listed CVE with a bunch of decorations. To make sense of those JSON files, check them against the [current schema](schema/schema-v1.1.0-dev.json). These JSON files are updated periodically as new information is released; new KEVs, new Nuclei templates, new EPSS scores, that sort of thing.

The data pipeline lives in this repo. Source data is checked out as Git submodules under `sources/`, the enrichment logic lives in `kevology/`, and the scripts in `bin/` generate, validate, and report on the published JSON. A fresh checkout needs the submodules initialized before the pipeline has all of its inputs; see [Getting started on Debian](#getting-started-on-debian) below for the full walkthrough, including the shallow checkouts that keep the big sources from eating your disk.

Some sources are large. `sources/metasploit-framework` keeps full Git history for commit-date lookups, but its working tree is limited to `modules/` because those are the files used by the enrichment pipeline.

The normal update entrypoint is:

```sh
./update.sh
```

That script updates the source submodules, regenerates `json/`, validates the generated files against the schema, and refreshes generated reports such as `reports/vendor-product-sorted-kevs.md`. If you're hacking on the pipeline, the most useful smaller pieces are:

```sh
./bin/generate_kev_contexts.rb
./bin/validator.rb
./bin/generate_vendor_product_report.sh
```

There's also a [Jupyter Notebook](kev-explore.ipynb) that steps through most of the findings detailed in the paper, but with fresh data (so you won't get exactly the same ratios as documented, but time and exploitation marches on).

## Getting started on Debian

These steps assume a fresh, current Debian install (tested on arm64 and should be the same on amd64) and a regular user with `sudo`. Budget disk space accordingly: the full set of source submodules is big, which is why two of them get shallow checkouts below. With the shallow checkouts below, `sources/` comes to roughly 7 GB (about 4.3 GB for `cvelistV5` and 2.7 GB for `epss_scores`), so 15 GB of free space is comfortable once you add Ruby, gems, and the OS itself.

### 1. System packages

```sh
sudo apt update
sudo apt install -y git curl jq pkg-config build-essential autoconf bison \
  libssl-dev libyaml-dev libreadline-dev zlib1g-dev libffi-dev libgdbm-dev \
  libncurses-dev libmagickwand-dev fonts-dejavu-core
```

What those are for:

- `git`, `curl`, `jq`: cloning, fetching, and the shell parts of the pipeline.
- `build-essential`, `autoconf`, `bison`, and the `lib*-dev` packages (except `libmagickwand-dev`): needed to compile Ruby with rbenv.
- `pkg-config`, `libmagickwand-dev`: needed to build the `rmagick` gem, which `gruff` pulls in for charts.
- `fonts-dejavu-core`: so charts have a font to draw labels with.

### 2. Ruby, via rbenv

Debian's packaged Ruby tends to lag, so use rbenv to get a current one:

```sh
git clone https://github.com/rbenv/rbenv.git ~/.rbenv
git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build

echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init - bash)"' >> ~/.bashrc
source ~/.bashrc

rbenv install 3.3.8
rbenv global 3.3.8
ruby -v
```

The compile takes a few minutes. If you run the pipeline from cron or any other non-interactive shell, make sure `~/.rbenv/shims` and `~/.rbenv/bin` are on that job's `PATH`, or you'll get `env: 'ruby': No such file or directory`.

### 3. Clone the repo and its submodules

`sources/cvelistV5` and `sources/epss_scores` are huge and only the current contents matter, so check them out shallow. Everything else gets a normal checkout:

```sh
git clone git@github.com:runZeroInc/kev-collider-data.git
cd kev-collider-data

git submodule update --init --depth 1 -- sources/cvelistV5 sources/epss_scores
git submodule update --init --recursive -- \
  sources/ctid sources/kev-data sources/metasploit-framework sources/nuclei-templates
```

Do the shallow ones first, so they're initialized with `--depth 1` before anything else touches them. A shallow submodule fetches the exact commit the superproject pins, not the tip of its branch. A later plain `git submodule update` is fine and keeps them shallow; only `git fetch --unshallow` inside one will pull its full history.

Please don't use a bare `git submodule update --init --recursive` on a first checkout unless you really do want every submodule's full history.

### 4. Install the gems

```sh
gem install bundler
bundle install
```

If `bundle install` fails building `rmagick`, double check that `libmagickwand-dev` and `pkg-config` from step 1 actually installed.

### 5. Run the pipeline

```sh
./update.sh
```

A clean run updates the submodules, regenerates `json/`, validates it against the schema, and refreshes the reports. Note that `update.sh` also commits and pushes the results, so if you're just kicking the tires, work on a fork or a throwaway branch, and don't be surprised by the push.

If a run dies partway through and leaves half-generated files in `json/`, `git status` will show them. Use `git restore .` to reset tracked files, remove any stray untracked `json/CVE-*` files, and run `./update.sh` again.

## Usage: KEV Collider

The power of KEV Collider becomes pretty apparent when using the built in filtering and sorting. Because it's a static website, there is no notion of sessions or cookies or anything like that, which means all the filtering ends up as GET request parameters. For example, for "Straight-Shot RCE" is really just:

```
https://www.runzero.com/kev-collider/?cvss.av=network&cvss.pr=none&cvss.ui=none&cvss.i=high
```

(aka, the CVSSv3.1 vectors of Access Vector: **Network**, Privileges Required: **None**, User Interaction: **None**, Integrity Impact: **High**). This means you can save these filters as bookmarks, pass them around with friends, fiddle with them offline, and other uses we haven't thought of yet.

If you come up with a particularly useful set of filters in your experimentation, let us know as a feature request, and we'll consider adding it as a preset filter!

## About runZero

runZero is an exposure management platform providing unrivaled visibility across your entire internal and external attack surface — covering IT, OT, IoT, mobile, and cloud. Uncover the unknowns, reveal elusive exposures, and target the true risks other tools miss. Give it a [try for free](https://runzero.com/try)!

