'use strict';

const cluster = require('cluster');
const irc = require('irc');
const config = require('./config.js');
const log = config.log.child({module: 'irc'});

function ellipsify(str, length) {
  if(!str)
    return '(empty)';

  if(str.length > length)
    return str.substring(0, length - 3) + '...';

  return str;
}

if(cluster.isMaster) {
  var _registered = false;
  var _ircClient = null;
  const _channelTargetMap = new Map();
  var _server, _nick, _options;

  config.on('irc/say', (message, worker) => {
    say(message.target, message.message);
  });

  function areObjectsEqual(a, b) {
    return Object.keys(a).every(key => a[key] === b[key]) && Object.keys(b).every(key => b[key] === a[key]);
  }

  config.on('change', newConfig => {
    if(!newConfig.irc || !newConfig.irc.server || !newConfig.irc.nick) {
      // No IRC
      if(_ircClient) {
        log.warn({messageId: 'lib/irc/closing-client'}, 'IRC configuration was removed, closing client.');
        _ircClient.disconnect('IRC was deconfigured');
        _ircClient = null;
      }

      return;
    }

    var newOptions = {
      port: 6667,
      encoding: 'utf8',
    };

    if(newConfig.irc.options) {
      Object.keys(newConfig.irc.options).forEach(key => {
        newOptions[key] = newConfig.irc.options[key];
      });
    }

    // Don't auto-reconnect; we'll manage that ourselves
    newOptions.autoConnect = false;
    newOptions.autoRejoin = false;

    // No retries -- this library doesn't tell us about connection drops,
    // which causes errors
    newOptions.retryCount = -1;

    // Apparently not all servers support PONGs back to clients; set the timeout to one week
    newOptions.millisecondsOfSilenceBeforePingSent = 7 * 24 * 60 * 60 * 1000;
    newOptions.millisecondsBeforePingTimeout = 7 * 24 * 60 * 60 * 1000;

    if(_ircClient && _server === newConfig.irc.server &&
        _nick === newConfig.irc.nick && areObjectsEqual(_options, newOptions)) {
      // Nothing's changed, leave things alone
      return;
    }

    if(_ircClient) {
      log.warn({messageId: 'lib/irc/closing-client-reconfig'}, 'Closing IRC client due to reconfiguration.');
      _ircClient.disconnect('Leaving to reconfigure IRC client');
      _ircClient = null;
    }

    _server = newConfig.irc.server;
    _nick = newConfig.irc.nick;
    _options = newOptions;

    log.info({messageId: 'lib/irc/connecting', options: _options}, `Connecting to IRC server ${_server} as nick ${_nick}`);

    _ircClient = new irc.Client(_server, _nick, _options);

    _ircClient.on('registered', () => {
      log.info({messageId: 'lib/irc/registered'}, 'Registered at IRC server');
      _registered = true;

      for(let target of _channelTargetMap.values())
        target.sendWaitingMessages();
    });

    _ircClient.on('abort', () => {
      if(_registered) {
        _registered = false;
        log.warn({messageId: 'lib/irc/disconnected'}, 'Disconnected from IRC server.');

        for(let target of _channelTargetMap.values())
          target.handlePart('Disconnected');
      }

      setTimeout(() => {
        _ircClient.connect();
      }, 1000);
    });

    _ircClient.on('error', message => {
      log.error({messageId: 'lib/irc/client-error', ircMessage: message}, `IRC client received an error: ${message}`);
    });

    _ircClient.on('join', (channel, nick, message) => {
      if(nick !== _nick)
        return;

      const target = getTarget(channel);

      if(!target)
        return;

      target.handleJoin();
    });

    _ircClient.on('part', (channel, nick, reason, message) => {
      if(nick !== _nick)
        return;

      const target = getTarget(channel);

      if(!target)
        return;

      target.handlePart(reason);
    });

    _ircClient.connect();
  });

  function ChannelTarget(name) {
    var _joining = false, _joined = false;
    const _waitingMessages = [];

    this.handleJoin = function handleJoin() {
      _joining = false;
      _joined = true;
      sendWaitingMessages();
    };

    this.handlePart = function handlePart(reason) {
      _joined = false;
      _joining = false;
      log.warn({messageId: 'lib/irc/channel-part', channel: name, reason: reason}, `Removed from channel ${name}: ${reason}`);
    };

    this.say = function say(message) {
      if(!message)
        return;

      message = ellipsify(message, 420);
      _waitingMessages.push(message);
      sendWaitingMessages();
    }

    function sendWaitingMessages() {
      if(!_registered || !_ircClient.conn)
        return;

      if(!_joined && !_joining) {
        log.info({messageId: 'lib/irc/channel-join-ask', channel: name}, `Asking to join channel ${name}.`);
        _ircClient.join(name);
        _joining = true;
        return;
      }

      while(_waitingMessages.length) {
        _ircClient.say(name, _waitingMessages.shift());
      }
    }

    this.sendWaitingMessages = sendWaitingMessages;
  }

  function getTarget(target) {
    if(target.startsWith('#')) {
      let sender = _channelTargetMap.get(target);

      if(!sender) {
        sender = new ChannelTarget(target);
        _channelTargetMap.set(target, sender);
      }

      return sender;
    }

    // TODO
    return null;
  }

  function say(target, message) {
    // Don't pile up messages if we don't expect we're going to send them
    if(!_ircClient) {
      log.warn({messageId: 'lib/irc/say/no-irc', target: target, ircMessage: message}, 'Attempting to talk to IRC, but no IRC server configured.');
      return;
    }

    var sender = getTarget(target);

    if(sender)
      sender.say(message);
  };

  /*this.close = function close() {
    ircClient.disconnect('Leaving');
  };*/

  module.exports.say = say;
}
else {
  // cluster worker
  function say(target, message) {
    process.send({cmd: 'irc/say', data: {target: target, message: message}});
  }

  module.exports.say = say;
}