const async = require('async');
const config = require('./config/config');
const request = require('request');
const util = require('util');
const fs = require('fs');
const NodeCache = require('node-cache');
const cache = new NodeCache({
  stdTTL: 3600
});
const MAX_PARALLEL_LOOKUPS = 1;
const MAX_ENTITIES_TO_BULK_LOOKUP = 5;
let Logger;
let requestOptions = {};
let domainBlackList = [];
let previousDomainBlackListAsString = '';
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlacklistRegex = null;
let ipBlacklistRegex = null;
let requestWithDefaults;
let token = '';

function _setupRegexBlacklists(options) {
  if (
    options.domainBlacklistRegex !== previousDomainRegexAsString &&
    options.domainBlacklistRegex.length === 0
  ) {
    Logger.debug('Removing Domain Blacklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlacklistRegex = null;
  } else {
    if (options.domainBlacklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlacklistRegex;
      Logger.debug(
        { domainBlacklistRegex: previousDomainRegexAsString },
        'Modifying Domain Blacklist Regex'
      );
      domainBlacklistRegex = new RegExp(options.domainBlacklistRegex, 'i');
    }
  }

  if (
    options.blacklist !== previousDomainBlackListAsString &&
    options.blacklist.length === 0
  ) {
    Logger.debug('Removing Domain Blacklist Filtering');
    previousDomainBlackListAsString = '';
    domainBlackList = null;
  } else {
    if (options.blacklist !== previousDomainBlackListAsString) {
      previousDomainBlackListAsString = options.blacklist;
      Logger.debug(
        { domainBlacklist: previousDomainBlackListAsString },
        'Modifying Domain Blacklist Regex'
      );
      domainBlackList = options.blacklist.split(',').map((item) => item.trim());
    }
  }

  if (
    options.ipBlacklistRegex !== previousIpRegexAsString &&
    options.ipBlacklistRegex.length === 0
  ) {
    Logger.debug('Removing IP Blacklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlacklistRegex = null;
  } else {
    if (options.ipBlacklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlacklistRegex;
      Logger.debug(
        { ipBlacklistRegex: previousIpRegexAsString },
        'Modifying IP Blacklist Regex'
      );
      ipBlacklistRegex = new RegExp(options.ipBlacklistRegex, 'i');
    }
  }
}

function _isEntityBlacklisted(entityObj, options) {
  if (domainBlackList.indexOf(entityObj.value) >= 0) {
    return true;
  }

  if (entityObj.isIPv4 && !entityObj.isPrivateIP) {
    if (ipBlacklistRegex !== null) {
      if (ipBlacklistRegex.test(entityObj.value)) {
        Logger.debug({ ip: entityObj.value }, 'Blocked BlackListed IP Lookup');
        return true;
      }
    }
  }

  if (entityObj.isDomain) {
    if (domainBlacklistRegex !== null) {
      if (domainBlacklistRegex.test(entityObj.value)) {
        Logger.debug({ domain: entityObj.value }, 'Blocked BlackListed Domain Lookup');
        return true;
      }
    }
  }

  return false;
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

  if (token) {
    callback(null, token);
    return;
  }

  request(
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
      if (err) {
        return callback(err);
      } else {
        Logger.trace('Good Archer login: ' + body.RequestedObject.SessionToken);
        cache.set(tokenCacheKey, body.RequestedObject.SessionToken);
        callback(null, body.RequestedObject.SessionToken);
      }
    }
  );
}

function chunk(arr, chunkSize) {
  const R = [];
  for (let i = 0, len = arr.length; i < len; i += chunkSize) {
    R.push(arr.slice(i, i + chunkSize));
  }
  return R;
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
  Logger.trace('options are', options);

  _setupRegexBlacklists(options);

  //Logger.debug(entities);

  async.each(
    entities,
    function (entityObj, next) {
      if (
        _isEntityBlacklisted(entityObj, options) ||
        (entityObj.type === 'domain' && !checkDNS) ||
        (entityObj.type === 'IPv6' && !checkv6) ||
        (entityObj.type === 'arch_apps' && !checkAPP) ||
        (entityObj.type === 'arch_devc' && !checkDID) ||
        (entityObj.type === 'arch_risk' && !checkRSK) ||
        (entityObj.type === 'arch_risk' && !checkRSK) ||
        (entityObj.type === 'arch_find' && !checkFND) ||
        (entityObj.type === 'arch_incd' && !checkINC)
      ) {
        lookupResults.push({ entity: entityObj, data: null }); //Cache the missed results
        next(null);
      } else {
        _lookupEntity(entityObj, options, function (err, result) {
          if (err) {
            next(err);
          } else {
            lookupResults.push(result);
            Logger.debug({ result: result }, 'Results pushed:');
            next(null);
          }
        });
      }
    },
    function (err) {
      Logger.debug({ lookupResults: lookupResults }, 'Result Values:');
      cb(err, lookupResults);
    }
  );
}

function _lookupEntity(entityObj, options, cb) {
  getAuthToken(options, (err, token) => {
    if (err) {
      Logger.error('Error getting Archer session token: ', err);
      return;
    }

    Logger.debug({ entityObj: entityObj }, 'Printing entity Object: ');
    //log.trace({archer: archer}, "Archer Check:");

    let requestOptions = {
      method: 'GET',
      headers: {
        Authorization: 'Archer session-id=' + token
      },
      json: true
    };

    if (!entityObj) {
      Logger.error('No value of entity!');
      return;
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

    Logger.debug({ uri: requestOptions.uri }, 'Request URI');

    requestWithDefaults(requestOptions, function (error, res, body) {
      if (error) {
        Logger.error({ error: error, res: res, body: body }, 'HTTP Request Error');
        return done(error);
      }

      Logger.debug(
        { body: body, statusCode: res ? res.statusCode : 'N/A' },
        'Result of Lookup'
      );

      //let result = {};

      if (res.statusCode === 200) {
        // we got data!
        let hitCount = body.value.length;
        if (hitCount > 0) {
          let hits = hitCount + ' hit';
          if (hitCount > 1) hits = hits + 's';
          Logger.debug(hits);
          // The lookup results returned is an array of lookup objects with the following format
          cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
              //// Required: this is the string value that is displayed in the template
              //entity_name: entityObj.value,
              // Required: These are the tags that are displayed in your template
              summary: [hits],
              // Data that you want to pass back to the notification window details block
              details: body
            }
          });
        }
      } else if (res.statusCode === 401) {
        // no authorization
        Logger.error({ err: '401 Error', detail: 'Unauthorized RSA Archer request.' });
        cb(err);
        return;
      } else {
        // unexpected status code
        Logger.debug({ err: body, detail: '${body.error}: ${body.message}' });
        cb(err);
        return;
      }
    });
  });
}

function getRequestOptions() {
  return JSON.parse(JSON.stringify(requestOptions));
}

function _generateArcherLinks(results) {
  let archerLinks = [];
  results.value.forEach((result) => {
    archerLinks.push({
      moduleID: result.ModuleId,
      contentID: result.ContentId,
      applicationName: result.AppliCatioName,
      keyField: result.KeyField
    });
  });
}

function _isMiss(body) {
  if (body && Array.isArray(body) && body.length === 0) {
    return true;
  }

  if (!body.data) {
    return true;
  }

  return false;
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

  //requestOptions.json = true;
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
