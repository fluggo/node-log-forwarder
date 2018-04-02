'use strict';

const crypto = require('crypto');
const d3 = require('d3');
const grok = require('node-grok');
const tz = require('timezone/loaded');

const esDateFormat = d3.timeFormat('%Y.%m.%d');
const fileDateFormat = d3.timeFormat('%Y-%m-%d');
const localHourFormat = d3.timeFormat('%H');

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

const patterns = grok.loadDefaultSync();

patterns.createPattern('%{DATE_US} %{HOUR}:%{MINUTE}:%{SECOND} [AP]M', 'FULLDATE');
patterns.createPattern('[0-9A-Z]{16}', 'PACKETID');
patterns.createPattern('[ R]', 'RESPONSEFLAG');
patterns.createPattern('[ A][ T][ D][ R]', 'FLAGS');

const startPattern = patterns.createPattern('^%{FULLDATE:eventTime} %{WORD:thread} %{WORD:eventType}\\s+%{GREEDYDATA:message}$');
const packetPattern = patterns.createPattern('^%{PACKETID} %{WORD:protocol} %{WORD} %{IPV4:clientIp}\\s+%{WORD:xid} %{RESPONSEFLAG:responseFlag} %{WORD:opcode} \\[%{WORD:hexflags} %{FLAGS:flags}\\s+%{WORD:responseCode}\\] %{WORD:questionType} +%{GREEDYDATA:questionName}$');

const eventTimeParse = d3.timeParse('%-m/%-d/%Y %-I:%M:%S %p');

function preprocess(ctx, line) {
  return line;
}

function process(ctx, line) {
  if(line === '' ||
    line.startsWith('\t') ||
    line.startsWith('DNS Server log file creation at ') ||
    line.startsWith('Log file wrap at ') ||
    line.startsWith('Message logging key '))
    return;

  const startParsed = startPattern.parseSync(line);

  if(!startParsed) {
    console.log('!!! FAILED TO PARSE ' + line);
    return;
  }

  if(startParsed.eventType === 'EVENT') {
    console.log('EVENT: ' + startParsed.message);
    return;
  }
  else if(startParsed.eventType !== 'PACKET') {
    console.log(`!!! UNKNOWN EVENT TYPE ${startParsed.eventType}: ${startParsed.message}`);
    return;
  }

  const parsed = packetPattern.parseSync(startParsed.message);

  if(!parsed) {
    console.log('!!! FAILED TO PARSE PACKET ' + line);
    return;
  }

  let result;

  if(parsed.responseFlag === 'R') {
    //console.log(JSON.stringify(parsed));
    let domainName = parseQName(parsed.questionName);

    if(domainName === '') {
      domainName = null;
    }
    else if(!domainName) {
      console.log(`!!! FAILED TO PARSE QNAME ${JSON.stringify(parsed.questionName, null, 2)} (${JSON.stringify(domainName, null, 2)})`);
      return;
    }

    domainName = domainName && domainName.toLowerCase();
    const domainList = makeDomainList(domainName);

    result = {
      log: {
        reportingIp: ctx.meta.remoteAddress,
        receivingPort: ctx.meta.localPort,
        receiveTime: ctx.meta.receiveTime,
        eventTime: eventTimeParse(startParsed.eventTime),
        source: {
          ip: parsed.clientIp,
        },
        target: {
          fqdn: domainName,
          fqdnBreakdown: domainList,
        },
        protocol: (parsed.protocol === 'UDP') ? 17 : 6,
      },
      dns: {
        packetId: parsed.packetId,
        opcode: parsed.opcode,
        responseCode: parsed.responseCode,
        flags: {
          authoritative: parsed.flags[0] === 'A',
          truncated: parsed.flags[1] === 'T',
          recursionDesired: parsed.flags[2] === 'D',
          recursionAvailable: parsed.flags[3] === 'R',
        },
        questionType: parsed.questionType,
        topDomain: domainList && domainList[0],
        secondaryDomain: domainList && domainList[1],
      }
    };

    if(!result.log.eventTime) {
      console.log(`---- FAILED TO PARSE eventTime ${parsed.eventTime}`);
      return;
    }

    //console.log(JSON.stringify(result, null, 2));
    ctx.sendElasticsearch('dns-' + esDateFormat(ctx.meta.receiveTime), 'dns');
    ctx.sendFile(`${ctx.meta.remoteAddress}/${fileDateFormat(ctx.meta.receiveTime)}/dns-${localHourFormat(ctx.meta.receiveTime)}.jsonlog`);

    return result;
  }
}

function parseQName(str) {
  if(str[0] !== '(')
    return null;

  let start = 0;
  const result = [];

  for(;;) {
    var end = str.indexOf(')', start);

    const count = +str.substring(start + 1, end);

    if(isNaN(count))
      return null;

    if(count === 0)
      return result.join('.');

    const wordStart = end + 1, wordEnd = wordStart + count;

    result.push(str.substring(end + 1, end + 1 + count));
    start = end + 1 + count;
  }
}

function makeDomainList(domain) {
  if(!domain)
    return null;

  const domains = [];
  const domainList = domain.split('.');

  for(let i = 1; i <= domainList.length; i++) {
    domains.push(domainList.slice(-i).join('.'));
  }

  return domains;
}
