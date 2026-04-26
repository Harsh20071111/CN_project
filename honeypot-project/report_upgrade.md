# Hybrid Banking System with Integrated Honeypot Security

## Overview
The traditional honeypot methodology often involves creating a single, vulnerable facade intended to lure attackers. However, when simulating a real-world enterprise environment (such as a banking portal), relying on a single entry point poses ethical and practical challenges. If a legitimate user inadvertently interacts with the system, attempting to computationally differentiate between a "real user" and a "hacker" based solely on credentials or behavioral heuristics on a fake login page is inherently flawed and risks crossing into unethical phishing territory.

To address this, we have upgraded our architecture to a **Dual-Layer Hybrid System**. This ensures safe, legitimate interaction for authorized users while maintaining a robust trap for malicious actors.

---

## The Dual-Layer Architecture

### 1. Legitimate Banking System (`/bank-login` and `/bank-dashboard`)
Designed exclusively for real users, this layer features:
- **True Authentication**: A secure login route (`/bank-login`) checking against a dedicated `users` database table.
- **Session Management**: Secure server-side sessions that grant access only to authenticated users.
- **Premium User Interface**: A modern, responsive, and visually distinct banking dashboard (`/bank-dashboard`) designed with professional aesthetics, enhancing user trust.

### 2. The Honeypot Layer (`/`)
Maintained as a separate, isolated route, this layer acts as the primary trap:
- **Decoy Login**: Operates at the root or exposed subdirectories where automated scanners and attackers typically strike first.
- **No Real Authentication**: Any credential entered is assumed to be an unauthorized access attempt.
- **Advanced Logging & Alerting**: Captures IP, location data, and credentials, storing them securely in the `logs` table and triggering email alerts upon persistent brute-force attacks (e.g., 5+ attempts).

---

## Why This Approach is Superior

1. **Clean Architecture**: By separating the legitimate user flow from the attacker flow, the codebase becomes more modular and maintainable.
2. **Ethical Compliance**: Eliminates the risk of inadvertently treating a real user as an attacker or collecting their real credentials under false pretenses. The legitimate portal is clearly defined and protected.
3. **Real-World Applicability**: This mirrors how actual enterprise systems deploy honeypots—by exposing a vulnerable-looking perimeter asset (like an outdated admin panel or generic login) while keeping the true employee/customer portal hidden or heavily authenticated elsewhere.

---

## Key Viva Talking Points

When presenting this project, emphasize the following:

> *"We recognized that trying to automatically classify real users versus hackers on a single fake login page was unreliable and ethically problematic. Therefore, we implemented a dual-layer system where legitimate users access a real banking interface with strong authentication, while attackers interacting with the honeypot are monitored separately. This ensures ethical handling of real users, provides a premium experience for them, and still enables robust attack detection and logging."*

---

## Conclusion
This upgrade elevates the project from a simple script into a **"Hybrid Banking System with Integrated Honeypot Security"**—a top-grade, professional implementation demonstrating not just technical skill, but architectural foresight and ethical responsibility.
