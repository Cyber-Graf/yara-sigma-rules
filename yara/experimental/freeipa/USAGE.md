Use the `cyber_graf_freeipa_rulepack.yar` as a central include — it aggregates all thematic rules under one file.

### 🧪 Usage

```bash
# Cyber Graf — FreeIPA Detection Pack
yara -r freeipa_rules.yar /target/path

# OR set include path explicitly:
export YARA_INCLUDE_PATH=.
yara freeipa_rules.yar /path