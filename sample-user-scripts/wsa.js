'use strict';

const crypto = require('crypto');
const d3 = require('d3');
const grok = require('node-grok');
const tz = require('timezone/loaded');

const dateFormat = d3.timeFormat('%Y.%m.%d');

var _lookupCounter = 1;
var _recordFinderBuffer = Buffer.allocUnsafe(2);

function shortenBase64(str) {
  var len = str.length;

  while(len && str[len - 1] === '=')
    len--;

  while(len && str[len - 1] === 'A')
    len--;

  return str.substr(0, len);
}

function makeRecordFinder() {
  if(++_lookupCounter >= 65535)
    _lookupCounter = 1;

  _recordFinderBuffer.writeUInt16LE(_lookupCounter, 0);
  return shortenBase64(_recordFinderBuffer.toString('base64'));
}

function preprocess(ctx, line) {
  return {
    reportingIp: ctx.meta.remoteAddress,
    receivingPort: ctx.meta.localPort,
    receivedTime: ctx.meta.receiveTime,
    eventTime: ctx.meta.receiveTime,
    tag: ['wsa'],
    message: (line instanceof Buffer) ? line.toString('utf8') : line,
    recordFinder: makeRecordFinder(),
  };
}


/***** WSA support *****/
const parseWsa = (() => {
  const patterns = grok.loadDefaultSync();

  patterns.createPattern('[A-Z][A-Z0-9_]+', 'UPPER_KEYWORD');
  patterns.createPattern('[^- ]+', 'POLICY_NAME');
  patterns.createPattern('[^,>]+', 'VERDICT');
  patterns.createPattern('[^"]+', 'QUOTED_VERDICT');

  const pattern = patterns.createPattern(
    '^<%{NONNEGINT}>%{MONTH:month} %{NONNEGINT:day} %{NONNEGINT:hour}:%{NONNEGINT:minute}:%{NONNEGINT:second} %{DATA:logName} %{DATA:logLevel}: ' +
    '%{BASE10NUM:timestamp} %{NONNEGINT:elapsedTime} %{IP:clientIp} ' +
    '%{UPPER_KEYWORD:transactionResult}/%{NONNEGINT:httpResponseCode} ' +
    '%{NONNEGINT:responseSize} %{NOTSPACE:httpMethod} %{NOTSPACE:url} %{NOTSPACE:username} ' +
    '%{UPPER_KEYWORD:upstreamConnection}/%{NOTSPACE:server} %{NOTSPACE:responseMimeType} ' +
    '%{UPPER_KEYWORD:aclDecision}-%{POLICY_NAME:decisionPolicy}-%{POLICY_NAME:identityPolicy}-%{POLICY_NAME:outboundMalwarePolicy}-%{POLICY_NAME:dataSecurityPolicy}-%{POLICY_NAME:externalDlpPolicy}-%{POLICY_NAME:routingPolicy} ' +
    '<%{VERDICT:transactionUrlCategory},%{VERDICT:reputationScore},%{VERDICT:webrootVerdict},"%{QUOTED_VERDICT:webrootSpywareName}",%{VERDICT:webrootThreatRisk},%{VERDICT:webrootThreatId},%{VERDICT:webrootTraceId},' +
      '%{VERDICT:mcafeeVerdict},"%{QUOTED_VERDICT:mcafeeFilename}",%{VERDICT:mcafeeScanError},%{VERDICT:mcafeeDetectionType},%{VERDICT:mcafeeVirusType},"%{QUOTED_VERDICT:mcafeeVirusName}",' +
      '%{VERDICT:sophosVerdict},%{VERDICT:sophosScanCode},"%{QUOTED_VERDICT:sophosFilename}","%{QUOTED_VERDICT:sophosVirusName}",' +
      '%{VERDICT:ciscoDataSecurityVerdict},%{VERDICT:externalDlpVerdict},%{VERDICT:requestUrlCategory},%{VERDICT:responseUrlCategory},"%{QUOTED_VERDICT:responseMalwareCategory}",' +
      '"%{QUOTED_VERDICT:reputationThreatType}","%{QUOTED_VERDICT:avcAppName}","%{QUOTED_VERDICT:avcAppType}","%{QUOTED_VERDICT:avcAppBehavior}",' +
      '"%{QUOTED_VERDICT:adultContentVerdict}",%{VERDICT:avgBandwidthKbps},%{VERDICT:bandwidthThrottled},%{VERDICT:anyConnectUserType},' +
      '"%{QUOTED_VERDICT:outboundMalwareVerdict}","%{QUOTED_VERDICT:outboundMalwareThreatName}",' +
      '%{VERDICT:ampVerdict},"%{QUOTED_VERDICT:ampThreatName}",%{VERDICT:ampReputationScore},%{VERDICT:ampUploaded},"%{QUOTED_VERDICT:ampFilename}","%{QUOTED_VERDICT:sha256Hash}">(?: [^ ]+ "[^"]+" [0-9]+ "[^"]+" %{NONNEGINT:requestSize})?');

  function undash(val) { return val === '-' ? undefined : val; }
  function undashNumber(val) { return val === '-' ? undefined : +val; }

  const malwareVerdicts = {
    '0': 'unknown',
    '1': 'not-scanned',
    '2': 'timeout',
    '3': 'error',
    '4': 'unscannable',
    '10': 'generic-spyware',
    '12': 'browser-helper-object',
    '13': 'adware',
    '14': 'system-monitor',
    '18': 'commercial-system-monitor',
    '19': 'dialer',
    '20': 'hijacker',
    '21': 'phishing-url',
    '22': 'trojan-downloader',
    '23': 'trojan-horse',
    '24': 'trojan-phisher',
    '25': 'worm',
    '26': 'encrypted-file',
    '27': 'virus',
    '33': 'other-malware',
    '34': 'pua',
    '35': 'aborted',
    '36': 'outbreak-heuristics',
    '37': 'known-malicious-or-high-risk'
  };

  function getMalwareVerdict(val) {
    if(val === '-')
      return undefined;

    return malwareVerdicts[val] || val;
  }

  const safeSearchVerdicts = {
    'ensrch': 'unsafe-search',
    'encrt': 'adult-content',
    'unsupp': 'unsupported-search',
    'err': 'error',
    '-': undefined,
  };

  function getAmpVerdict(val) {
    if(val === '-')
      return undefined;

    val = +val;

    if(val === 0)
      return 'safe';
    else if(val === 1)
      return 'not-scanned';
    else if(val === 2)
      return 'scan-timed-out';
    else if(val === 3)
      return 'error';
    else if(val > 3)
      return 'malicious';

    return 'unknown';
  }

  function parse(line) {
    var parsed = pattern.parseSync(line.message);

    if(!parsed)
      return null;

    var username = (parsed.username === '-') ? undefined : parsed.username.substr(1, parsed.username.length - 2);
    var samName = username && username.split('@')[0].toUpperCase();

    // Strip number off the end of the ACL decision; docs say to ignore it
    parsed.aclDecision = parsed.aclDecision.replace(/_[0-9]+$/, '');

    parsed.reputationScore = +parsed.reputationScore;
    var domains = [];

    if(parsed.server) {
      parsed.server = parsed.server.toLowerCase();

      if(parsed.server.match(/[a-z]/)) {
        var domainList = parsed.server.split('.');

        for(let i = 2; i <= domainList.length; i++) {
          domains.push(domainList.slice(-i).join('.'));
        }
      }
    }

    var result = {
      log: {
        eventTime: new Date(+parsed.timestamp * 1000),
        reportingIp: parsed.logName.replace(/:$/, ''),
        receivingPort: line.receivingPort,
        receivedTime: line.receivedTime,
        recordFinder: line.recordFinder,
        source: {
          ip: parsed.clientIp,
          samName: samName,
        },
        target: {
          fqdn: undash(parsed.server),
          fqdnBreakdown: domains.length ? domains : undefined,
        },
        tag: ['wsa'],
        message: line.message,
      },

      wsa: {
        elapsedTime: +parsed.elapsedTime,
        transactionResult: parsed.transactionResult,
        upstreamConnection: parsed.upstreamConnection,
        upstreamServer: undash(parsed.server),
        urlCategory: undash(parsed.transactionUrlCategory),
        aclDecision: parsed.aclDecision,
        aclDecisionBase: parsed.aclDecision.split('_')[0],
        avgBandwidthKbps: +parsed.avgBandwidthKbps,
        bandwidthThrottled: parsed.bandwidthThrottled === '1',
        anyConnectUserType: undash(parsed.anyConnectUserType),

        request: {
          httpMethod: parsed.httpMethod,
          clientIp: parsed.clientIp,
          url: parsed.url,
          username: username,
          samName: samName,
          urlCategory: undash(parsed.requestUrlCategory),
          outboundMalwareVerdict: undash(parsed.outboundMalwareVerdict),
          outboundMalwareThreatName: undash(parsed.outboundMalwareThreatName),
          size: parsed.requestSize && +parsed.requestSize,
        },
        response: {
          httpResponseCode: +parsed.httpResponseCode,
          size: +parsed.responseSize,
          mimeType: undash(parsed.responseMimeType),
          urlCategory: undash(parsed.responseUrlCategory),
          malwareCategory: undash(parsed.responseMalwareCategory),
          sha256Hash: undash(parsed.sha256Hash),
        },

        verdict: {
          webReputationScore: isNaN(parsed.reputationScore) ? undefined : parsed.reputationScore,
          ciscoDataSecurity: (parsed.ciscoDataSecurityVerdict === '-' ? undefined : (parsed.ciscoDataSecurityVerdict === '1' ? 'block' : 'allow')),
          externalDlp: (parsed.externalDlpVerdict === '-' ? undefined : (parsed.externalDlpVerdict === '1' ? 'block' : 'allow')),
          reputationThreatType: undash(parsed.reputationThreatType),
          safeSearch: safeSearchVerdicts[parsed.adultContentVerdict],
          webroot: {
            verdict: getMalwareVerdict(parsed.webrootVerdict),
            spywareName: undash(parsed.webrootSpywareName),
            threatRisk: undashNumber(parsed.webrootThreatRisk),
            threatId: undashNumber(parsed.webrootThreatId),
            traceId: undashNumber(parsed.webrootTraceId),
          },
          mcafee: {
            verdict: getMalwareVerdict(parsed.mcafeeVerdict),
            filename: undash(parsed.mcafeeFilename),
            scanError: undash(parsed.mcafeeScanError),
            detectionType: undash(parsed.mcafeeDetectionType),
            virusType: undash(parsed.mcafeeVirusType),
            virusName: undash(parsed.mcafeeVirusName),
          },
          sophos: {
            verdict: getMalwareVerdict(parsed.sophosVerdict),
            scanCode: undash(parsed.sophosScanCode),
            filename: undash(parsed.sophosFilename),
            virusName: undash(parsed.sophosVirusName),
          },
          avc: {
            appName: undash(parsed.avcAppName),
            appType: undash(parsed.avcAppType),
            appBehavior: undash(parsed.avcAppBehavior),
          },
          amp: {
            verdict: getAmpVerdict(parsed.ampVerdict),
            threatName: undash(parsed.ampThreatName),
            reputationScore: undashNumber(parsed.ampReputationScore),
            uploaded: parsed.ampUploaded === '1',
            filename: undash(parsed.ampFilename),
          },
        },

        policies: {
          decision: parsed.decisionPolicy,
          identity: parsed.identityPolicy,
          outboundMalware: parsed.outboundMalwarePolicy,
          dataSecurity: parsed.dataSecurityPolicy,
          externalDlp: parsed.externalDlpPolicy,
          routingPolicy: parsed.routingPolicy,
        },

      },
    };

    if(!result.wsa.verdict.webroot.verdict)
      result.wsa.verdict.webroot = undefined;

    if(!result.wsa.verdict.mcafee.verdict)
      result.wsa.verdict.mcafee = undefined;

    if(!result.wsa.verdict.sophos.verdict)
      result.wsa.verdict.sophos = undefined;

    if(!result.wsa.verdict.avc.appName)
      result.wsa.verdict.avc = undefined;

    if(!result.wsa.verdict.amp.verdict)
      result.wsa.verdict.amp = undefined;

    return result;
  }

  return parse;
})();


function process(ctx, msg) {
  const wsa = parseWsa(msg);

  if(wsa) {
    ctx.sendElasticsearch('wsalog-' + dateFormat(wsa.log.receivedTime), 'wsalog');

    ctx.meta.type = 'wsa';

    const buffer = Buffer.allocUnsafe(8);
    buffer.writeUIntLE(new Date(wsa.log.receivedTime).getTime(), 0, 8);

    ctx.meta.finderUrl = 'https://localhost/investigator/?wsa=' + encodeURIComponent(shortenBase64(buffer.toString('base64')) + '-' + msg.recordFinder);

    if(wsa.wsa.aclDecision.startsWith('BLOCK_') || wsa.wsa.aclDecision.startsWith('DROP_') || wsa.wsa.aclDecision.startsWith('NO_')) {
      if(wsa.wsa.urlCategory !== 'IW_adv' && wsa.wsa.verdict.reputationThreatType !== 'othermalware' &&
          wsa.wsa.aclDecision !== 'BLOCK_WBRS' &&
          wsa.wsa.aclDecision !== 'DROP_WBRS')
        ctx.sendIrc('#infosec_wsa_alerts');
    }

    return wsa;
  }
  else {
    //ctx.sendIrc('#infosec_alerts_dev');

    const buffer = Buffer.allocUnsafe(8);
    buffer.writeUIntLE(new Date(msg.eventTime).getTime(), 0, 8);

    ctx.meta.finderUrl = 'https://localhost/investigator/?sl=' + encodeURIComponent(shortenBase64(buffer.toString('base64')) + '-' + msg.recordFinder);
    ctx.sendElasticsearch('raw-syslog-' + dateFormat(msg.eventTime), 'raw-syslog');

    return { log: msg };
  }
}


/****** IRC ******/

function ellipsify(str, length) {
  if(str.length > length)
    return str.substring(0, length - 3) + '...';

  return str;
}

function ircEscape(str) {
  return str.replace(/[\x00-\x1f]/g, ' ');
}

function formatIrc(ctx, msg) {
  var str = '';

  if(ctx.meta.type === 'wsa') {
    if(msg.wsa.aclDecision.startsWith('BLOCK_') || msg.wsa.aclDecision.startsWith('DROP_') || msg.wsa.aclDecision.startsWith('NO_')) {
      // White text on red background
      str += '\x030,4 ' + ircEscape(msg.wsa.aclDecision) + ' \x03 ';

      if(msg.wsa.urlCategory) {
        str += msg.wsa.urlCategory + ' ';
      }

      if(msg.wsa.verdict.reputationThreatType) {
        str += '(' + msg.wsa.verdict.reputationThreatType + ') ';
      }
    }
    else if(msg.wsa.aclDecision.startsWith('MONITOR_') || msg.wsa.aclDecision.startsWith('DECRYPT_')) {
      // White text on orange background
      str += '\x030,7 ' + ircEscape(msg.wsa.aclDecision) + ' \x03 ';

      if(msg.wsa.urlCategory) {
        str += msg.wsa.urlCategory + ' ';
      }

      if(msg.wsa.verdict.reputationThreatType) {
        str += '(' + msg.wsa.verdict.reputationThreatType + ') ';
      }

      if(msg.wsa.response.httpResponseCode) {
        str += msg.wsa.response.httpResponseCode + ' ';
      }
    }
    else if(msg.wsa.aclDecision !== 'DEFAULT_CASE') {
      str += '\x030,3 ' + ircEscape(msg.wsa.aclDecision) + ' \x03 ';

      if(msg.wsa.response.httpResponseCode) {
        str += msg.wsa.response.httpResponseCode + ' ';
      }
    }

    str += ircEscape(msg.wsa.request.httpMethod + ' ' + ellipsify(msg.wsa.upstreamServer || msg.wsa.request.url || '[unknown]', 100));

    const addlInfo = [];

    if(msg.wsa.request.username)
      addlInfo.push('as ' + ircEscape(msg.wsa.request.samName || msg.wsa.request.username));

    if(msg.wsa.request.clientIp)
      addlInfo.push('from ' + ircEscape(msg.wsa.request.clientIp));

    if(addlInfo.length)
      str += ' \x0314(' + addlInfo.join(' ') + ')';

    str += '\x0315 ' + ctx.meta.finderUrl;

    return str;
  }
  else {
    return ellipsify(ircEscape(msg.message), 250);
  }
}
