'use strict';

const config = require('./config.js');
const log = config.log.child({module: 'slack'});

const WebClient = require('@slack/client').WebClient;

var _webClient;
var _token;

config.on('change', newConfig => {
  if(!newConfig.slack || !newConfig.slack.token) {
    // No IRC
    if(_webClient) {
      log.warn({messageId: 'lib/slack/removing'}, 'Slack configuration was removed.');
      _webClient = null;
    }

    return;
  }

  const newOptions = {
    token: newConfig.slack.token,
  };

  if(_webClient && _token === newConfig.token) {
    // Nothing's changed, leave things alone
    return;
  }

  if(_webClient) {
    log.warn({messageId: 'lib/slack/closing-client-reconfig'}, 'Closing Slack client due to reconfiguration.');
    _webClient = null;
  }

  _token = newConfig.slack.token;

  log.info({messageId: 'lib/slack/connecting'}, `Connecting to Slack server.`);

  _webClient = new WebClient(_token);
});

function postMessage(target, text, options) {
  options = options || {};

  // Don't pile up messages if we don't expect we're going to send them
  if(!_webClient) {
    log.warn({messageId: 'lib/slack/postMessage/no-client', target: target}, 'Attempting to talk to Slack, but no Slack server configured.');
    return;
  }

  _webClient.chat.postMessage(target, text, options, (err, res) => {
    if(err) {
      log.error({err: err, target: target, messageId: 'lib/slack/postMessage/error'}, `Failed to send message to Slack channel ${target}.`);
    }

    console.log('Slack message sent');
  });
}

module.exports.postMessage = postMessage;
