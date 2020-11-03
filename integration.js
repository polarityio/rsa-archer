const async = require('async');
const config = require('./config/config');
const request = require('request');
const util = require('util');
const fs = require('fs');
const NodeCache = require('node-cache');
const cache = new NodeCache({
  stdTTL: 3600
});
let Logger;
let requestOptions = {};
let domainBlockList = [];
let previousDomainBlockListAsString = '';
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;
let requestWithDefaults;
let token = '';

function _setupRegexBlocklists(options) {
  if (
    options.domainBlocklistRegex !== previousDomainRegexAsString &&
    options.domainBlocklistRegex.length === 0
  ) {
    Logger.trace('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
    previousDomainRegexAsString = options.domainBlocklistRegex;
    Logger.trace(
      { domainBlocklistRegex: previousDomainRegexAsString },
      'Modifying Domain Blocklist Regex'
    );
    domainBlocklistRegex = new RegExp(previousDomainRegexAsString, 'i');
  }

  if (
    options.blocklist !== previousDomainBlockListAsString &&
    options.blocklist.length === 0
  ) {
    Logger.trace('Removing Domain Blocklist Filtering');
    previousDomainBlockListAsString = '';
    domainBlockList = null;
  } else if (options.blocklist !== previousDomainBlockListAsString) {
    previousDomainBlockListAsString = options.blocklist;
    Logger.trace(
      { domainBlocklist: previousDomainBlockListAsString },
      'Modifying Domain Blocklist Regex'
    );
    domainBlockList = options.blocklist.split(',').map((item) => item.trim());
  }

  if (
    options.ipBlocklistRegex !== previousIpRegexAsString &&
    options.ipBlocklistRegex.length === 0
  ) {
    Logger.trace('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else if (options.ipBlocklistRegex !== previousIpRegexAsString) {
    previousIpRegexAsString = options.ipBlocklistRegex;
    Logger.trace(
      { ipBlocklistRegex: previousIpRegexAsString },
      'Modifying IP Blocklist Regex'
    );
    ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
  }
}

const _isEntityBlocklisted = (entityObj, options) => {
  const entityFoundInBlocklist = domainBlockList.indexOf(entityObj.value) >= 0;

  const entityIsBlocklistedIp =
    entityObj.isIPv4 &&
    !entityObj.isPrivateIP &&
    ipBlocklistRegex !== null &&
    ipBlocklistRegex.test(entityObj.value);

  if (entityIsBlocklistedIp)
    Logger.trace({ ip: entityObj.value }, 'Blocked BlockListed IP Lookup');

  const entityIsBlocklistedDomain =
    entityObj.isDomain &&
    domainBlocklistRegex !== null &&
    domainBlocklistRegex.test(entityObj.value);

  if (entityIsBlocklistedDomain)
    Logger.trace({ domain: entityObj.value }, 'Blocked BlockListed Domain Lookup');

  return entityFoundInBlocklist || entityIsBlocklistedIp || entityIsBlocklistedDomain;
}

const getTokenCacheKey = (options) =>
  options.host +
  options.userName +
  options.instanceId +
  options.userPass +
  options.userDomain;

function getAuthToken(options, callback) {
  let tokenCacheKey = getTokenCacheKey(options);
  token = cache.get(tokenCacheKey);

  if (token) return callback(null, token);

  requestWithDefaults(
    {
      uri: `${options.host}/api/core/security/login`,
      body: {
        Username: options.userName,
        Password: options.userPass,
        InstanceName: options.instanceId,
        UserDomain: options.userdomain
      },
      json: true,
      method: 'POST'
    },
    (err, resp, body) => {
      if (err) return callback(err);

      if (
        resp.statusCode !== 200 ||
        !(body && body.RequestedObject && body.RequestedObject.SessionToken)
      ) {
        return callback({
          statusCode: resp ? resp.statusCode : "N/A",
          err: body,
          detail: 'Failed to Login to Archer'
        });
      }

      Logger.trace('Good Archer login: ' + body.RequestedObject.SessionToken);
      cache.set(tokenCacheKey, body.RequestedObject.SessionToken);
      callback(null, body.RequestedObject.SessionToken);
    }
  );
}


function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];
  let checkDNS = options.lookupDomains;
  let checkv6 = options.lookupIPv6;
  let checkFND = options.lookupFnds;
  let checkDID = options.lookupDids;
  let checkAPP = options.lookupApps;
  let checkINC = options.lookupIncs;
  let checkRSK = options.lookupRsks;

  Logger.trace('starting lookup');
  Logger.trace({ options }, 'Options');

  _setupRegexBlocklists(options);

  async.each(
    entities,
    function (entityObj, next) {
      if (
        _isEntityBlocklisted(entityObj, options) ||
        (entityObj.type === 'domain' && !checkDNS) ||
        (entityObj.type === 'IPv6' && !checkv6) ||
        (entityObj.type === 'custom' &&
          ((entityObj.types.indexOf('custom.arch_apps') >= 0 && !checkAPP) ||
            (entityObj.types.indexOf('custom.arch_devc') >= 0 && !checkDID) ||
            (entityObj.types.indexOf('custom.arch_risk') >= 0 && !checkRSK) ||
            (entityObj.types.indexOf('custom.arch_risk') >= 0 && !checkRSK) ||
            (entityObj.types.indexOf('custom.arch_find') >= 0 && !checkFND) ||
            (entityObj.types.indexOf('custom.arch_incd') >= 0 && !checkINC)))
      ) {
        lookupResults.push({ entity: entityObj, data: null }); //Cache the missed results
        return next(null);
      } 
      _lookupEntity(entityObj, options, function (err, result) {
        if (err) return next(err);
        
        lookupResults.push(result);
        Logger.trace({ result }, 'Results pushed:');
        next(null);
      });
    },
    function (err) {
      Logger.trace({ lookupResults, err }, 'Result Values:');
      cb(
        err,
        lookupResults.filter((i) => i)
      );
    }
  );
}

function _lookupEntity(entityObj, options, cb) {
  getAuthToken(options, (err, token) => {
    if (err) {
      Logger.error({ err }, 'Error getting Archer session token');
      return cb(err)
    }

    Logger.trace({ entityObj }, 'Printing entity Object');

    let requestOptions = {
      method: 'GET',
      headers: {
        Authorization: 'Archer session-id=' + token
      },
      json: true
    };

    if (!(entityObj && entityObj.value)) {
      Logger.error('No value of entity!');
      return cb({ err: entityObj, detail: 'No value of entity!' });
    }

    requestOptions.uri = `${options.host}/api/V2/internal/ContentHits?$filter=Keyword%20eq%20%27${entityObj.value}%27&$top=10`;
    requestOptions.qs = {
      whois: true,
      hostDetails: true,
      ipDetails: true,
      linkedAssetCounts: true,
      recentPDNS: true,
      subDomainPDNS: true,
      openPorts: true,
      certificates: true
    };

    Logger.trace({ uri: requestOptions.uri }, 'Request URI');

    requestWithDefaults(requestOptions, function (error, res, body) {
      if (error) {
        Logger.error({ error, res, body }, 'HTTP Request Error');
        return cb(error);
      }

      Logger.trace(
        { body, statusCode: res ? res.statusCode : 'N/A' },
        'Result of Lookup'
      );


      if (res.statusCode === 200) {
        let hitCount = body.value.length;
        if (hitCount > 0) {
          let hits = hitCount + ' hit';
          if (hitCount > 1) hits = hits + 's';
          Logger.trace({ hits }, 'Hits');
          // The lookup results returned is an array of lookup objects with the following format
          return cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
              // Required: this is the string value that is displayed in the template
              //entity_name: entityObj.value,
              // Required: These are the tags that are displayed in your template
              summary: [hits],
              // Data that you want to pass back to the notification window details block
              details: body
            }
          });
        }
        return cb(null, {
            entity: entityObj,
            data: null
          });
      } else if (res.statusCode === 401) {
        // no authorization
        Logger.error({ err: '401 Error', detail: 'Unauthorized RSA Archer request.' });
        return cb(err);
      }
      // unexpected status code
      Logger.trace({ err: body, detail: `${body.error}: ${body.message}` });
      return cb(err);
      
    });
  });
}


function startup(logger) {
  Logger = logger;
  let defaults = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    requestOptions.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    requestOptions.key = fs.readFileSync(config.request.key);
  }

  if (
    typeof config.request.passphrase === 'string' &&
    config.request.passphrase.length > 0
  ) {
    requestOptions.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    requestOptions.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    requestOptions.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' &&
      options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(
    errors,
    options,
    'host',
    'You must provide an Authentication Host option.'
  );
  validateStringOption(
    errors,
    options,
    'userName',
    'You must provide an Archer API username.'
  );
  validateStringOption(errors, options, 'userPass', 'You must provide a password.');

  callback(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions
};
