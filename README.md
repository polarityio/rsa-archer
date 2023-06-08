# Polarity RSA Archer Integration

The Polarity RSA Archer integration allows freeform text searching for IPs, domains as well as tracking IDs for core applications such as Devices, Applications, Risk Registry, Security Incidents and Findings in your Archer instance.

For more information on RSA Archer, please visit: [official website] (https://www.rsa.com/en-us/products/integrated-risk-management).

Check out the integration in action:

![Archer](https://i.imgur.com/PMpdwRy.png)

## RSA Archer Integration Options

### Archer Server URL
The Archer server to use for querying data (no trailing slash)

### User Name
The username to use for authentication.

### User Password
The password to use for authentication.

### Instance ID
The instance ID, if required for login.

### Domain
The user domain, if required for login.

### Lookup IPv6 Addresses
If checked, the integration will lookup IPv6 addresses in addition to IPv4.

### IP Block List Regex
IPs that match the given regex will not be looked up (if blank, no IPs will be block listed).

### Lookup Domains
If checked, the integration will lookup valid domain names.

### Blocklist Domains
Comma delimited list of domains that you do not want to lookup.

### Domain Block List Regex
Domains that match the given regex will not be looked up (if blank, no domains will be block listed).

### Lookup Archer Finding IDs
If checked, the integration will the default Archer Findings tracking IDs (FND-XXXXX).

### Lookup Archer Device IDs
If checked, the integration will the default Archer Devices tracking IDs (DID-XXXXX).

### Lookup Archer Application IDs
If checked, the integration will the default Archer Application tracking IDs (APPID-XXXXX).

### Lookup Archer Security Incident IDs
If checked, the integration will the default Archer Security Incident tracking IDs (INC-XXXXX).

### Lookup Archer Risk Register IDs
If checked, the integration will the default Archer Risk Register tracking IDs (RSK-XXXXX).

### Direct Search
Check if you want each Archer search to be an exact match with found entities



## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
