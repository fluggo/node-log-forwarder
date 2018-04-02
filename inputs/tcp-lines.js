'use strict';

const net = require('net');
const tls = require('tls');
const readline = require('readline');
const config = require('../lib/config.js');
const watch = require('../lib/watch.js');
const uuid = require('uuid/v4');
const cluster = require('cluster');

function input(name) {
  const log = config.log.child({module: 'input/tcp-lines', input: name});

  function digestConfig(config) {
    var result = {
      script: config.script || null,
      port: config.port,
      host: config.host || null,
      cert: config.cert,
      key: config.key,
      passphrase: config.passphrase,
      encoding: config.encoding || 'utf8',
    };

    return result;
  }

  var oldConfig = digestConfig({});
  var host = null, port = null;
  var script = {};
  var scriptWatcher = null;
  var server = null;
  var sockets = new Set();
  var _firstScript = true;
  var _receivedCount = 0, _droppedCount = 0, _errorCount = 0;

  this.config = function takeConfig(newConfig) {
    newConfig = digestConfig(newConfig);

    if(oldConfig.script !== newConfig.script) {
      if(scriptWatcher) {
        scriptWatcher.close();
        scriptWatcher = null;
      }
    }

    if(oldConfig.host !== newConfig.host || oldConfig.port !== newConfig.port ||
        oldConfig.cert !== newConfig.cert ||
        oldConfig.key !== newConfig.key ||
        oldConfig.passphrase !== newConfig.passphrase) {
      // Leave all existing connections open, but reconfigure the socket
      if(server) {
        server.close();
        server = null;
      }
    }

    if(!scriptWatcher) {
      scriptWatcher = watch.watchScript(newConfig.script);

      scriptWatcher.on('change', newScript => {
        (_firstScript ? log.info : log.warn).call(log, {messageId: 'input/tcp-lines/new-script', script: newConfig.script}, `Loading new script ${newConfig.script}.`);
        script = newScript;
        _firstScript = false;
      });

      scriptWatcher.on('script-error', err => {
        log.warn({messageId: 'input/tcp-lines/script-error', script: newConfig.script, err: err}, `Failed to load new script ${newConfig.script}.`)
      });
    }

    if(!server && !cluster.isMaster) {
      function handleSocket(socket) {
        sockets.add(socket);

        socket.setEncoding(newConfig.encoding);

        const address = socket.address();
        const remoteAddress = socket.remoteAddress;
        const localPort = socket.localPort;
        const socketLog = log.child({remoteAddress: remoteAddress, localPort: localPort, activityId: uuid()});

        socketLog.info({messageId: 'input/tcp-lines/new-connection'},
          `New TCP-lines connection from ${remoteAddress} on port ${localPort}.`);

        function processLineWorker(line) {
          _receivedCount++;
          var ctx = new config.messageContext(script, {remoteAddress: remoteAddress, localPort: localPort, receiveTime: new Date()});
          var originalLine = line;

          try {
            if(script.preprocess) {
              line = script.preprocess(ctx, line);
            }
            else {
              line = {msg: line};
            }

            if(!line) {
              _droppedCount++;
              return;
            }
          }
          catch(err) {
            socketLog.warn({messageId: 'input/tcp-lines/preprocess-error', err: err, line: originalLine}, 'Error while preparing line.');
            _errorCount++;
            return;
          }

          config.queue(ctx, line);
        }

        const rl = readline.createInterface({input: socket});

        socket.on('error', err => {
          socketLog.info({messageId: 'input/tcp-lines/connection-error', err: err}, 'Connection error.');
        });

        socket.on('close', () => {
          socketLog.info({messageId: 'input/tcp-lines/connection-closed'}, `Connection from ${remoteAddress} on port ${localPort} closed.`);

          rl.close();
          sockets.delete(socket);
        });

        rl.on('line', processLineWorker);
      }

      if(newConfig.cert) {
        // TLS-based connection
        console.log('Making TLS server');
        server = tls.createServer({
          key: newConfig.key,
          cert: newConfig.cert,
          passphrase: newConfig.passphrase
        }, handleSocket);
      }
      else {
        // Regular connection
        console.log(`making regular server on port ${newConfig.port}`);
        server = net.createServer(handleSocket);
      }

      server.on('error', err => {
        log.fatal({messageId: 'input/tcp-lines/server-error', err: err}, 'Error on server socket.');
      });

      server.listen({port: newConfig.port, host: newConfig.host || '0.0.0.0'});
    }

    oldConfig = newConfig;
  }

  this.getStats = function getStats() {
    const result = {
      connectionCount: sockets.size,
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
