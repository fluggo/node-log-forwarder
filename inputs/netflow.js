'use strict';

const config = require('../lib/config.js');
const watch = require('../lib/watch.js');
const Collector = require('node-netflowv9');
const cluster = require('cluster');

const decNumRule = {
  1: "o['$name']=buf.readUInt8($pos);",
  2: "o['$name']=buf.readUInt16BE($pos);",
  3: "o['$name']=buf.readUInt8($pos)*65536+buf.readUInt16BE($pos+1);",
  4: "o['$name']=buf.readUInt32BE($pos);",
  5: "o['$name']=buf.readUInt8($pos)*4294967296+buf.readUInt32BE($pos+1);",
  6: "o['$name']=buf.readUInt16BE($pos)*4294967296+buf.readUInt32BE($pos+2);",
  8: "o['$name']=buf.readUInt32BE($pos)*4294967296+buf.readUInt32BE($pos+4);"
};

function input(name) {
  const log = config.log.child({module: 'input/netflow', input: name});

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
  var collector = null;
  var _firstScript = true;
  var _receivedCount = 0, _droppedCount = 0, _errorCount = 0, _receivedPacketCount = 0;
  var address = null;

  function handlePacket(packet) {
    const receivedTime = new Date();

    packet.flows.forEach(function(flow) {
      _receivedCount++;
      var ctx = new config.messageContext(script, {
        remoteAddress: packet.rinfo.address,
        localPort: address.port,
        receivedTime: receivedTime,
        netflowVersion: packet.header.version,
        packetHeader: packet.header,
      });

      try {
        if(script.preprocess) {
          flow = script.preprocess(ctx, flow);
        }

        if(!flow) {
          _droppedCount++;
          return;
        }
      }
      catch(err) {
        log.error({messageId: 'input/netflow/preprocess-error', err: err, msg: flow}, 'Error while preparing message.');
        _errorCount++;
        return;
      }

      config.queue(ctx, flow);
    });
  }

  function startServer(newConfig) {
    if(collector)
      return;

    if(cluster.isMaster)
      return;

    collector = new Collector({
      host: newConfig.host || '0.0.0.0',
      port: newConfig.port,
      nfTypes: {
        40005: { name: 'firewallEvent', compileRule: decNumRule }
      },
      cb: handlePacket
    });

    collector.server.once('listening', () => {
      address = collector.server.address();
    });

    collector.server.once('error', err => {
      log.error({messageId: 'input/netflow/server-error', err: err}, 'UDP socket error.');
      collector.server.close();
      startServer(newConfig);
    });
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
      if(collector) {
        collector.server.close();
        collector = null;
      }
    }

    if(!scriptWatcher) {
      scriptWatcher = watch.watchScript(newConfig.script);

      scriptWatcher.on('change', newScript => {
        (_firstScript ? log.info : log.warn).call(log, {messageId: 'input/netflow/new-script', script: newConfig.script},
          `Loading new script ${newConfig.script} for Netflow input ${name}.`);
        script = newScript;
        _firstScript = false;
      });

      scriptWatcher.on('script-error', err => {
        log.warn({messageId: 'input/netflow/script-error', script: newConfig.script, err: err},
          `Failed to load new script ${newConfig.script}.`)
      });
    }

    startServer(newConfig);

    oldConfig = newConfig;
  }

  this.getStats = function getStats() {
    const result = {
      receivedCount: _receivedCount,
      receivedPacketCount: _receivedPacketCount,
      droppedCount: _droppedCount,
      errorCount: _errorCount,
    };

    _receivedCount = 0;
    _droppedCount = 0;
    _errorCount = 0;
    _receivedPacketCount = 0;

    return result;
  };

  this.close = function close() {
    if(collector) {
      collector.server.close();
      collector = null;
    }
  };
}

module.exports.create = name => new input(name);

