## 🧬 Cyber Graf — YARA & SIGMA Rules

This repository contains custom detection rules developed by the [Cyber Graf](https://t.me/cyber_graf) project. 
These rules focus on real-world threats, misconfigurations, and offensive techniques seen in malware, cloud, identity systems, and advanced adversary behavior.

## 📁 Repository Structure

The rules are organized into three main categories for clarity and scalability:
```
yara-sigma-rules/
├── attack_rules/ # Techniques and methods used in offensive operations
├── malware_rules/ # Specific malware families and loaders
├── threat_actor_rules/ # Rules tailored to specific threat actor activity
```

## Quality Policy

- ✅ MITRE ATT&CK tags  
- ✅ Custom UUIDs per rule  
- ✅ Minimal false positives, context-aware  
- ✅ Fully documented meta fields  
- ⚠️ `experimental` status until confirmed in production

## 📬 Feedback & Contributions

Found something broken? Using the rules at scale?  
Open an [issue](https://github.com/Cyber-Graf/yara-sigma-rules/issues), submit a pull request, or contact via [Cyber Graf](https://t.me/cyber_graf).