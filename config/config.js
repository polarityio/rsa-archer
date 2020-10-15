module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'RSA Archer',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'ARCH',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description: 'Polarity RSA Archer integration',
  entityTypes: ['ip', 'domain'],
  customTypes: [
    {
      key: 'arch_apps',
      regex: /APPID-[0-9]{2,7}/
    },
    {
      key: 'arch_devc',
      regex: /DID-[0-9]{2,7}/
    },
    {
      key: 'arch_risk',
      regex: /RKS-[0-9]{2,7}/
    },
    {
      key: 'arch_find',
      regex: /FND-[0-9]{2,7}/
    },
    {
      key: 'arch_incd',
      regex: /INC-[0-9]{2,7}/
    }
  ],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/archer.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/archer-block.js'
    },
    template: {
      file: './templates/archer-block.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the Archer integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the Archer integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the Archer integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the Archer integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: '',
    /**
     * If set to false, the integeration will ignore SSL errors.  This will allow the integration to connect
     * to Archer servers without valid SSL certificates.  Please note that we do NOT recommending setting this
     * to false in a production environment.
     */
    rejectUnauthorized: true
  },
  logging: {
    // directory is relative to the this integrations directory
    // e.g., if the integration is in /app/polarity-server/integrations/virustotal
    // and you set directoryPath to be `integration-logs` then your logs will go to
    // `/app/polarity-server/integrations/integration-logs`
    // You can also set an absolute path.  If you set an absolute path you must ensure that
    // the directory you specify is writable by the `polarityd:polarityd` user and group.

    //directoryPath: '/var/log/polarity-integrations',
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'host',
      name: 'Archer Server',
      description: 'The Archer server to use for querying data (no trailing slash)',
      default: 'https://grc.archer.rsa.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'userName',
      name: 'API User Name',
      description: 'The username to use for authentication.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'userPass',
      name: 'API User Password',
      description: 'The password to use for authentication.',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'instanceId',
      name: 'Instance ID',
      description: 'The instance ID, if required for login.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'userDomain',
      name: 'Domain',
      description: 'The user domain, if required for login.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'lookupIPv6',
      name: 'Lookup IPv6 Addresses',
      description:
        'If checked, the integration will lookup IPv6 addresses in addition to IPv4.',
      default: false,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'ipBlocklistRegex',
      name: 'IP Block List Regex',
      description:
        'IPs that match the given regex will not be looked up (if blank, no IPs will be block listed).',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'lookupDomains',
      name: 'Lookup Domains',
      description: 'If checked, the integration will lookup valid domain names.',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'blocklist',
      name: 'Blocklist Domains',
      description: 'Comma delimited list of domains that you do not want to lookup.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'domainBlocklistRegex',
      name: 'Domain Block List Regex',
      description:
        'Domains that match the given regex will not be looked up (if blank, no domains will be block listed).',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'lookupFnds',
      name: 'Lookup Archer Finding IDs',
      description:
        'If checked, the integration will the default Archer Findings tracking IDs (FND-XXXXX).',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupDids',
      name: 'Lookup Archer Finding IDs',
      description:
        'If checked, the integration will the default Archer Devices tracking IDs (DID-XXXXX).',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupApps',
      name: 'Lookup Archer Application IDs',
      description:
        'If checked, the integration will the default Archer Application tracking IDs (APPID-XXXXX).',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupIncs',
      name: 'Lookup Archer Security Incident IDs',
      description:
        'If checked, the integration will the default Archer Security Incident tracking IDs (INC-XXXXX).',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'lookupRsks',
      name: 'Lookup Archer Risk Register IDs',
      description:
        'If checked, the integration will the default Archer Risk Register tracking IDs (RSK-XXXXX).',
      default: true,
      type: 'boolean',
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'directSearch',
      name: 'Direct Search',
      description:
        'Check if you want each Archer search to be an exact match with found entities',
      default: false,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: false
    }
  ]
};
