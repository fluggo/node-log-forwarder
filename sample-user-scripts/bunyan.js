'use strict';

const crypto = require('crypto');
const d3 = require('d3');

const dateFormat = d3.timeFormat('%Y.%m.%d');
const fileDateFormat = d3.timeFormat('%Y-%m-%d');
const localHourFormat = d3.timeFormat('%H');

function ellipsify(str, length) {
  if(str.length > length)
    return str.substring(0, length - 3) + '...';

  return str;
}

function ircEscape(str) {
  return str.replace(/[\x00-\x1f]/g, ' ');
}

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
  return JSON.parse(line);
}

const productionSystems = new Set(['vm-prodsystem']);

function process(ctx, msg) {
  const result = {
    log: {
      recordFinder: makeRecordFinder(),
      reportingIp: ctx.meta.remoteAddress,
      receivingPort: ctx.meta.localPort,
      receivedTime: ctx.meta.receiveTime,
      eventTime: new Date(msg.time),
      source: {
        ip: ctx.meta.remoteAddress,
        hostname: msg.hostname,
      },
      tag: ['bunyan'],
    },
    bunyan: msg,
  };

  const buffer = Buffer.allocUnsafe(8);
  buffer.writeUIntLE(ctx.meta.receiveTime.getTime(), 0, 8);

  ctx.meta.finderUrl = 'https://localhost/' + encodeURIComponent(shortenBase64(buffer.toString('base64')) + '-' + result.log.recordFinder);

  if((msg.interest && msg.interest >= 3) || msg.level >= 40) {
    if(productionSystems.has(msg.hostname))
      ctx.sendIrc('#alerts');
    else
      ctx.sendIrc('#alerts_dev');
  }

  if(msg.name === 'Investigator' && (msg.messageId === 'wiki/createArticle/article-created' ||
    msg.messageId === 'wiki/createArticle/article-needs-review' ||
    msg.messageId === 'wiki/updateArticle/article-changed' ||
    msg.messageId === 'wiki/updateArticle/article-needs-review' ||
    msg.messageId === 'wiki/updateArticle/article-renamed' ||
    msg.messageId === 'wiki/deleteArticle/article-deleted')) {

    if(productionSystems.has(msg.hostname))
      ctx.sendIrc('#wiki');
    else
      ctx.sendIrc('#wiki_dev');
  }

  ctx.sendElasticsearch(`bunyan-${dateFormat(new Date(ctx.meta.receiveTime))}`, 'bunyan');
  ctx.sendFile(`${ctx.meta.remoteAddress}/${fileDateFormat(new Date(ctx.meta.receiveTime))}/bunyan-${localHourFormat(new Date(ctx.meta.receiveTime))}.jsonlog`);

  return result;
}

function formatBunyanIrc(ctx, fullMsg) {
  const msg = fullMsg.bunyan;
  var str = '';

  var interest = msg.interest || 3;

  if(interest === 1) {
    str += '\x02\x033 \u2193\u2193 \x03\x02 ';
  }
  else if(interest === 2) {
    str += '\x02 \u2193 \x02 ';
  }
  else if(interest === 3) {
  }
  else if(interest === 4) {
    str += '\x030,7 \u2191 \x03 ';
  }
  else if(interest === 5) {
    str += '\x030,4 \u2191\u2191 \x03 ';
  }

  if(msg.level <= 19) {
    str += 'TRACE ';
  }
  else if(msg.level <= 29) {
    str += '\x02\x033Debug\x03\x02 ';
  }
  else if(msg.level <= 39) {
    str += '\x02Info\x02 ';
  }
  else if(msg.level <= 49) {
    str += '\x02\x036Warning\x03\x02 ';
  }
  else if(msg.level <= 59) {
    str += '\x030,4 ERROR \x03 ';
  }
  else {
    str += '\x030,4 ! FATAL ! \x03 ';
  }

  if(msg.securityRelevant) {
    str += '\x02\x034Security\x03\x02 ';
  }

  if(msg.name) {
    str += ircEscape(ellipsify(msg.name, 60)) + ': ';
  }

  if(msg.module) {
    str += ircEscape(ellipsify(msg.module, 30)) + ': ';
  }

  var message = ircEscape(msg.msg);

  if(msg.err && msg.err.name) {
    message += ' \x034' + ircEscape(msg.err.name);

    if(msg.err.message)
      message += ': ' + ircEscape(msg.err.message);
  }

  str += ellipsify(message, 150);

  const addlInfo = [];

  if(msg.hostname)
    addlInfo.push('from ' + ircEscape(msg.hostname));

  if(addlInfo.length)
    str += ' \x0314(' + addlInfo.join(' ') + ')';

  str += '\x0315 ' + ctx.meta.finderUrl;

  return str;
}

function formatIrc(ctx, fullMsg) {
  const msg = fullMsg.bunyan;

  if(msg.name === 'Investigator' && msg.messageId === 'wiki/createArticle/article-created') {
    return `\x0300,03 CREATE \x0f ${ircEscape(msg.user)} created ${ircEscape(msg.id)}\x0315 https://localhost/investigator/wiki/article/${ircEscape(msg.id)}`;
  }
  if(msg.name === 'Investigator' && msg.messageId === 'wiki/createArticle/article-needs-review') {
    return `\x0300,03 CREATE \x0f \x0300,04 NEEDS REVIEW \x0f ${ircEscape(msg.user)} created ${ircEscape(msg.id)}\x0315 https://localhost/investigator/wiki/article/${ircEscape(msg.id)}`;
  }
  else if(msg.name === 'Investigator' && msg.messageId === 'wiki/updateArticle/article-changed') {
    return `\x0300,02 UPDATE \x0f ${ircEscape(msg.user)} updated ${ircEscape(msg.id)}\x0315 https://localhost/investigator/wiki/article/${ircEscape(msg.id)}`;
  }
  else if(msg.name === 'Investigator' && msg.messageId === 'wiki/updateArticle/article-needs-review') {
    return `\x0300,02 UPDATE \x0f \x0300,04 NEEDS REVIEW \x0f ${ircEscape(msg.user)} updated ${ircEscape(msg.id)}\x0315 https://localhost/investigator/wiki/article/${ircEscape(msg.id)}`;
  }
  else if(msg.name === 'Investigator' && msg.messageId === 'wiki/updateArticle/article-renamed') {
    return `\x0300,02 RENAME \x0f ${ircEscape(msg.user)} renamed ${ircEscape(msg.oldId)} to ${ircEscape(msg.id)}\x0315 https://localhost/investigator/wiki/article/${ircEscape(msg.id)}`;
  }
  else if(msg.name === 'Investigator' && msg.messageId === 'wiki/deleteArticle/article-deleted') {
    return `\x0300,04 DELETE \x0f ${ircEscape(msg.user)} deleted ${ircEscape(msg.id)}\x0315 https://localhost/investigator/wiki/article/${ircEscape(msg.id)}`;
  }
  else {
    return formatBunyanIrc(ctx, fullMsg);
  }
}
