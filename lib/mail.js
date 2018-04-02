'use strict';

const cluster = require('cluster');
const config = require('./config.js');
const log = config.log.child({module: 'lib/mail'});
const nodemailer = require('nodemailer');

var _oldConfig = null;
var _transport = null;

config.on('change', newConfig => {
  var mailConfig = newConfig.mail;

  var newConfigJson = JSON.stringify(mailConfig && mailConfig.transportOptions);
  var oldConfigJson = JSON.stringify(_oldConfig && _oldConfig.transportOptions);

  if(newConfigJson !== oldConfigJson) {
    if(_transport) {
      log.warn({messageId: 'lib/mail/closing-old-transport', config: JSON.parse(newConfigJson)},
        'Closing Nodemailer transport due to new configuration.');

      if(_transport.close)
        _transport.close();

      _transport = null;
    }
  }

  if(!mailConfig || !mailConfig.transportOptions)
    return;

  if(!_transport) {
    (_oldConfig ? log.warn : log.info).call(log, {messageId: 'lib/mail/new-transport', config: JSON.parse(newConfigJson)},
      'Creating new Nodemailer transport due to new configuration.');
    _transport = nodemailer.createTransport(JSON.parse(newConfigJson));
  }

  _oldConfig = mailConfig;
});

function sendMail(data) {
  if(!_transport) {
    log.warn({messageId: 'lib/mail/sendMail/no-config', data: data}, 'Attempting to send mail, but no transport configured.');
    return;
  }

  _transport.sendMail(data, (err, result) => {
    if(err) {
      log.warn({messageId: 'lib/mail/sendMail/failed', data: data, err: err}, 'Sending mail failed outright.');
      return;
    }

    if(result.rejected.length) {
      log.warn({messageId: 'lib/mail/sendMail/rejected', data: data, result: result}, `Mail sending failed to the following recipients: ${result.rejected}`);
    }
  });
}

module.exports.sendMail = sendMail;
