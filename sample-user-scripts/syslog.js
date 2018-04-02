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
    message: (line instanceof Buffer) ? line.toString('latin1') : line,
    tag: ['raw'],
    recordFinder: makeRecordFinder(),
  };
}

function process(ctx, msg) {
  const buffer = Buffer.allocUnsafe(8);
  buffer.writeUIntLE(new Date(msg.eventTime).getTime(), 0, 8);

  ctx.meta.finderUrl = 'https://localhost/investigator/?sl=' + encodeURIComponent(shortenBase64(buffer.toString('base64')) + '-' + msg.recordFinder);
  ctx.sendElasticsearch('raw-syslog-' + dateFormat(msg.eventTime), 'raw-syslog');

  return { log: msg };
}


/****** IRC ******/

function ellipsify(str, length) {
  if(str.length > length)
    return str.substring(0, length - 3) + '...';

  return str;
}

function ircEscape(str) {
  if(!str)
    return '(unknown)';

  return str.replace(/[\x00-\x1f]/g, ' ');
}

function formatIrc(ctx, msg) {
  return ellipsify(ircEscape(msg.log.message), 250);
}
