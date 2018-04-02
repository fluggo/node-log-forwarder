'use strict';

const dgram = require('dgram');
const config = require('../lib/config.js');
const watch = require('../lib/watch.js');
const cluster = require('cluster');

function input(name) {
  const log = config.log.child({module: 'input/udp', input: name});

  function digestConfig(config) {
    var result = {
      script: config.script || null,
      port: config.port,
      host: config.host || null,
    };

    return result;
  }

  var oldConfig = digestConfig({});
  var host = null, port = null;
  var script = {};
  var scriptWatcher = null;
  var server = null;
  var _firstScript = true;
  var _receivedCount = 0, _droppedCount = 0, _errorCount = 0;

  function startServer(newConfig) {
    if(cluster.isMaster)
      return;

    if(!server) {
      var address = null;
      server = dgram.createSocket('udp4');

      server.on('listening', () => {
        address = server.address();
      });

      server.on('error', err => {
        log.error({messageId: 'input/udp/server-error', err: err}, 'UDP socket error.');
        server.close();
        startServer(newConfig);
      });

      server.on('message', (msg, rinfo) => {
        _receivedCount++;
        var ctx = new config.messageContext(script, {remoteAddress: rinfo.address, localPort: address.port, receiveTime: new Date()});

        try {
          if(script.preprocess) {
            msg = script.preprocess(ctx, msg);
          }
          else {
            msg = {remoteAddress: rinfo.address, localPort: address.port, receiveTime: ctx.meta.receiveTime, msg: msg.toString('utf8')};
          }

          if(!msg) {
            _droppedCount++;
            return;
          }
        }
        catch(err) {
          log.error({messageId: 'input/udp/preprocess-error', err: err, msg: msg}, 'Error while preparing message.');
          _errorCount++;
          return;
        }

        config.queue(ctx, msg);
      });

      server.bind(newConfig.port, newConfig.host || '0.0.0.0');
    }
  }

  this.config = function takeConfig(newConfig) {
    newConfig = digestConfig(newConfig);

    if(oldConfig.script !== newConfig.script) {
      if(scriptWatcher) {
        scriptWatcher.close();
        scriptWatcher = null;
      }
    }

    if(oldConfig.host !== newConfig.host || oldConfig.port !== newConfig.port) {
      // Leave all existing connections open, but reconfigure the socket
      if(server) {
        server.close();
        server = null;
      }
    }

    if(!scriptWatcher) {
      scriptWatcher = watch.watchScript(newConfig.script);

      scriptWatcher.on('change', newScript => {
        (_firstScript ? log.info : log.warn).call(log, {messageId: 'input/udp/new-script', script: newConfig.script},
          `Loading new script ${newConfig.script} for UDP input ${name}.`);
        script = newScript;
        _firstScript = false;
      });

      scriptWatcher.on('script-error', err => {
        log.warn({messageId: 'input/udp/script-error', script: newConfig.script, err: err},
          `Failed to load new script ${newConfig.script}.`)
      });
    }

    startServer(newConfig);

    oldConfig = newConfig;
  }

  this.getStats = function getStats() {
    const result = {
      receivedCount: _receivedCount,
      droppedCount: _droppedCount,
      errorCount: _errorCount,
    };

    _receivedCount = 0;
    _droppedCount = 0;
    _errorCount = 0;

    return result;
  };

  this.close = function close() {
    if(server) {
      server.close();
      server = null;
    }
  };
}

module.exports.create = name => new input(name);
