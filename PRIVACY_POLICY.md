# Privacy Policy

**Last updated: February 22, 2026**

## Simple Proxy Client ("the App")

This Privacy Policy describes how the App handles user information. By using the App, you agree to the practices described below.

## Information We Collect

**We do not collect, store, or transmit any personal data to external servers controlled by us.**

The App operates as a local VPN client. All configuration data (server addresses, ports, credentials) is stored **locally on your device** using Android SharedPreferences and is never transmitted to any third party.

### Data Processed Locally

- **Proxy node configuration**: Server host, port, and authentication credentials you enter are stored only on your device.
- **Network traffic**: When the VPN is active, your network traffic is routed through the proxy server you configure. The App itself does not inspect, log, or store the contents of your traffic.

### Data NOT Collected

- No personal identifiers (name, email, phone number)
- No device identifiers (IMEI, advertising ID)
- No location data
- No usage analytics or telemetry
- No crash reports sent to external services
- No cookies or tracking technologies

## VPN Service

The App uses the Android `VpnService` API to create a local VPN tunnel on your device. Network traffic is forwarded to a proxy server **that you configure yourself**. The App developer does not operate, control, or have access to the proxy servers you choose to use.

## Third-Party Services

The App does **not** integrate any third-party SDKs, analytics, advertising, or tracking services.

## Data Sharing

We do not sell, trade, or transfer your data to any third parties. Since no personal data is collected, there is nothing to share.

## Data Retention

All configuration data is stored locally on your device. You can delete it at any time by clearing the App's data or uninstalling the App.

## Children's Privacy

The App is not directed at children under the age of 13. We do not knowingly collect any personal information from children. Since the App collects no personal data from any user, no special provisions are required.

## Security

Proxy connections use encrypted protocols to protect data in transit between your device and the configured proxy server. All sensitive configuration (such as credentials) is stored locally on your device.

## Changes to This Policy

We may update this Privacy Policy from time to time. Changes will be reflected by updating the "Last updated" date at the top of this document.

## Contact

If you have any questions about this Privacy Policy, please open an issue on our GitHub repository:

- https://github.com/zUZWqEHF/simple-proxy-server/issues
