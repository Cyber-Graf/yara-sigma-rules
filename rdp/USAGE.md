Use `cyber_graf_rdp_rulepack.yml` to explore and manage themed SIGMA rulesets (e.g. RDP, cloud, privilege escalation).

### 🧪 Usage

```bash
# Convert a rule to Elastic DSL
sigmac -t es-qs sigma/rdp/rdp_bruteforce_then_success.yml

# Batch convert all rules in pack
for file in sigma/rdp/*.yml; do
  sigmac -t splunk "$file"
done