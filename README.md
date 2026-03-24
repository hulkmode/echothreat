# Echo<Threat
<p align="center">
<img src=https://github.com/user-attachments/assets/091b0f07-4ffd-4aa9-8128-eb2e1b7f7350 width="300"/>
</p>

**Echo<Threat** is a modular synthetic log generation tool designed for detection engineering and simulation-based verification workflows.

It enables teams to generate authentic ECS-aligned logs using YAML configs and Jinja2 templates, perfect for tuning, backtesting, or verifying detection logic at scale.

## Why Echo<Threat?

Detection rules often stall in the **verification** phase, not for lack of ideas, but for lack of authentic data to test against.

Echo<Threat solves this by letting you:

- Simulate realistic logs across multiple Windows event sources (Security, Sysmon)
- Generate one or thousands of events, dynamically randomized
- Define behavioral chains (e.g., file drop → C2 → Mass Logon → New Service)
- Ingest directly into your SIEM (Elastic, Splunk, etc.) via NDJSON

## Project Structure

```
echothreat/
├── echothreat.py               # CLI input / core logic
├── configs/                    # YAML input values for each event
├── generators/
│   └── windows_log_generator.py # Renders log output from template + config
├── templates/                  # Jinja2 templates (e.g., security_4624_elastic.j2)
├── utils/
│   └── random.py               # rand() function for dynamic value generation
├── presets/                    # Multi-step attack chain definitions (YAML)
├── output/                     # Rendered logs (file, filebeat-ready)
```

## Features

-  ECS-native field support
-  NDJSON output (Elastic-compatible)
-  Modular template system with `rand()` for host/user/IP
-  Preset chains using `count:` and `throttle:` logic
-  Ingest pipeline compatibility (`sim.host_name → host.name`)
-  CLI flags to control every step of the simulation

## Maintainer

Echo<Threat was created and is maintained by **Hal Denton**  
Originally released under **DEATHGroup Labs LLC**

"Special thanks to Black Hills Information Security (BHIS) for supporting the detection engineering community and pushing verification standards forward."

## License & Usage

**EchoThreat** is built in public to support the detection engineering community. To ensure this tool remains freely available for practitioners while protecting the work from commercial exploitation, this project is licensed under the **Apache License 2.0 with the Commons Clause**.

### What this means for you:
* ✅ **You CAN use it for free:** Whether you are an individual researcher, a student, or a security team at a massive Fortune 500 corporation, you are completely free to use EchoThreat internally to generate logs, test your SIEM, and tune your detection logic. 
* ✅ **You CAN modify it:** You are free to tweak the code, build new Jinja2 templates, and write custom YAML configs to fit your specific environment.
* ❌ **You CANNOT sell it:** You are strictly prohibited from selling EchoThreat, hosting it as a paid commercial service, or wrapping this code into a proprietary, paid Enterprise Security product. 

**Attribution:**
If you use, modify, or share this project, you must preserve the original copyright notices and provide clear attribution to **Hal Denton** and the **EchoThreat** project. 

*(Note: Prior to March 24, 2026, this project was licensed under the MIT License. All subsequent updates, features, and releases are governed by the Apache 2.0 + Commons Clause).*

For the exact legal terms, please review the `LICENSE` file in the root of this repository.

## Tutorials
### Echo<Threat
- [Introducing EchoThreat - Expedite Detection Engineering w/ Hal Denton](https://www.youtube.com/live/-fQFkrZAWmM)
### Detection Engineering LifeCycle
- [Detection Engineering Alert Disposition w/ Hal & Paul](https://www.youtube.com/watch?v=ASau2WoGsRQ)
