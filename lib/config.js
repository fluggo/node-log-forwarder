'use strict';

const cluster = require('cluster');
const bunyan = require('bunyan');
const log = bunyan.createLogger({
  name: cluster.isMaster ? 'node-log-forwarder master' : 'node-log-forwarder worker',
  serializers: bunyan.stdSerializers,   // https://github.com/trentm/node-bunyan/issues/369
  workerId: cluster.isMaster ? undefined : cluster.worker.id,
  streams: [
    {
      level: 'debug',
      stream: require('bunyan-tcp').createBunyanStream({server: 'localhost', port: 5022}),
      type: 'raw',
      closeOnExit: true
    },
    {
      level: 'error',
      stream: process.stdout,
    }
  ]
});
const async = require('async');
const d3 = require('d3');

const path = require('path');
const watch = require('./watch.js');
const stripJsonComments = require('strip-json-comments');
const EventEmitter = require('events');

module.exports = new EventEmitter();
module.exports.log = log;
module.exports.config = {};

// Have errors transform to JSON gracefully
// http://stackoverflow.com/questions/18391212/is-it-not-possible-to-stringify-an-error-using-json-stringify
if(!('toJSON' in Error.prototype)) {
  Object.defineProperty(Error.prototype, 'toJSON', {
    value: function () {
      const alt = {};

      for(let key of Object.getOwnPropertyNames(this)) {
        alt[key] = this[key];
      }

      return alt;
    },
    configurable: true,
    writable: true
  });
}

function loadCerts() {
  const fs = require('fs');
  const rawCerts = fs.readFileSync('/etc/ssl/certs/ca-certificates.crt', {encoding: 'utf8'});
  const certs = [];
  var cert = [];

  rawCerts.split('\n').forEach(function(line) {
    if(line.length === 0)
      return;

    cert.push(line);
    if(line.match(/-END CERTIFICATE-/)) {
      certs.push(cert.join('\n'));
      cert = [];
    }
  });

  return certs;
}

module.exports.loadCerts = loadCerts;

const es = require('./es.js');
const irc = require('./irc.js');
const slack = require('./slack.js');
const mail = require('./mail.js');
const file = require('./file.js');

var inputModules = new Map();

function reregisterModules(newConfig) {
  if(!newConfig.inputs)
    return;

  var seenInputs = new Set();

  Object.keys(newConfig.inputs).forEach(key => {
    seenInputs.add(key);
    var module = inputModules.get(key);

    if(!module) {
      module = require('../' + newConfig.inputs[key].module).create(key);
      inputModules.set(key, module);
    }

    module.config(newConfig.inputs[key]);
  });

  Array.from(inputModules.keys()).forEach(key => {
    if(!seenInputs.has(key)) {
      inputModules.get(key).close();
      inputModules.delete(key);
    }
  });
}

if(cluster.isMaster) {
  // Republish IPC events as raised events
  cluster.on('message', (worker, message) => {
    if(!message.cmd) {
      log.warn({messageId: 'lib/config/invalid-ipc', message: message}, 'IPC message sent without command');
      return;
    }

    module.exports.emit(message.cmd, message.data, worker);
  });

  const configPath = path.join(__dirname, '../config.json');
  
  const configWatcher = watch.watchFile(configPath, 'utf8');
  var _firstLoad = true;
  var timer;

  configWatcher.on('change', contents => {
    if(!contents) {
      if(_firstLoad) {
        log.error({messageId: 'lib/config/no-config'}, "Configuration file doesn't exist, waiting for one");
      }
      else {
        log.error({messageId: 'lib/config/config-deleted'}, 'Configuration file deleted, continuing with known configuration');
      }

      return;
    }

    (_firstLoad ? log.info : log.warn).call(log, {messageId: 'lib/config/load-new-config', contents: contents}, 'Loading new configuration');

    _firstLoad = false;

    try {
      module.exports.config = JSON.parse(stripJsonComments(contents));
    }
    catch(err) {
      log.error({messageId: 'lib/config/config-load-failed', err: err, contents: contents},
        'Failed to load new configuration; check your config file syntax.');
      return;
    }

    reregisterModules(module.exports.config);
    module.exports.emit('change', module.exports.config);

    // Let all the workers know, too
    for(let id in cluster.workers) {
      cluster.workers[id].send({cmd: 'config/change', data: {config: module.exports.config}});
    }
  });

  configWatcher.on('error', err => {
    log.fatal({messageId: 'lib/config/watcher-error', err:err}, 'Configuration file watcher encountered an error');
  });

  cluster.on('online', worker => {
    // Let the new worker know what the config is
    worker.send({cmd: 'config/change', data: {config: module.exports.config}});
  });
}
else {
  // Republish IPC events as raised events
  process.on('message', message => {
    if(!message.cmd) {
      log.warn({messageId: 'lib/config/invalid-ipc', message: message}, 'IPC message sent without command');
      return;
    }

    module.exports.emit(message.cmd, message.data);
  });

  var flightQueue = async.queue((task, callback) => {
    // TODO: Post-process and queue for delivery
  }, 100);

  function defaultFormatIrc(ctx, data) {
    return data.message || data.msg || JSON.stringify(data);
  }

  function defaultFormatSlack(ctx, data) {
    return {text: data.message || data.msg || JSON.stringify(data), parse: 'full'};
  }

  function defaultFormatEmail(ctx, data) {
    return {
      from: {name: 'Logbot', address: 'no-reply@logbot.logbot'},
      subject: data.message || data.msg || 'Log mail',
      text: data.message || data.msg || JSON.stringify(data, null, 2),
    }
  }

  function makeMessageContextFunction() {
    function messageContext(scriptObj, meta) {
      this.scriptObj = scriptObj;
      this.meta = meta;
      this.ircTargets = undefined;
      this.emailTargets = undefined;
      this.elasticsearchTargets = undefined;
      this.fileWrites = undefined;
      this.slackTargets = undefined;
    }

    messageContext.prototype.sendIrc = function sendIrc(target) {
      if(!this.ircTargets) {
        this.ircTargets = new Set();
      }

      this.ircTargets.add(target);
    };

    messageContext.prototype.sendMail = function sendMail(target) {
      if(!this.emailTargets) {
        this.emailTargets = [];
      }

      this.emailTargets.push(target);
    };

    messageContext.prototype.sendElasticsearch = function sendElasticsearch(index, type) {
      if(!this.elasticsearchTargets) {
        this.elasticsearchTargets = new Map();
      }

      this.elasticsearchTargets.set(index, type);
    };

    messageContext.prototype.sendFile = function sendFile(filePath, data) {
      if(!this.fileWrites) {
        this.fileWrites = [];
      }

      this.fileWrites.push({path: filePath, data: data});
    };

    messageContext.prototype.sendSlack = function sendSlack(target) {
      if(!this.slackTargets) {
        this.slackTargets = new Set();
      }

      this.slackTargets.add(target);
    };

    messageContext.prototype.postProcess = function(ctx, msg) {
      if(this.fileWrites) {
        for(let write of this.fileWrites) {
          if(!write.data) {
            write.data = JSON.stringify(msg) + '\n';
          }
          else if((typeof write.data === 'object') && !(write.data instanceof Buffer)) {
            write.data = JSON.stringify(write.data) + '\n';
          }

          file.write(write.path, write.data || msg);
        }
      }

      if(this.ircTargets) {
        let formatted = (this.scriptObj.formatIrc || defaultFormatIrc)(ctx, msg);

        for(let target of this.ircTargets) {
          irc.say(target, formatted);
        }
      }

      if(this.slackTargets) {
        let formatted = (this.scriptObj.formatSlack || defaultFormatSlack)(ctx, msg);

        for(let target of this.slackTargets) {
          if(typeof formatted === 'string')
            slack.postMessage(target, formatted, {});
          else
            slack.postMessage(target, null, formatted);
        }
      }

      if(this.elasticsearchTargets) {
        for(let entry of this.elasticsearchTargets) {
          es.push(entry[0], entry[1], msg);
        }
      }

      if(this.emailTargets) {
        let formatted = (this.scriptObj.formatEmail || defaultFormatEmail)(ctx, msg);
        formatted.to = this.emailTargets;

        mail.sendMail(formatted);
      }
    };

    log.debug('Saving new message context function.');

    module.exports.messageContext = messageContext;
  }

  module.exports.on('config/change', message => {
    log.debug({messageId: 'lib/config/received-new-config'}, 'Received new configuration.');
    module.exports.config = message.config;
    module.exports.emit('change', module.exports.config);

    reregisterModules(module.exports.config);
    makeMessageContextFunction();
  });

  var messagesProcessed = 0;

  module.exports.queue = function queue(ctx, msg) {
    if(typeof ctx.scriptObj.process === 'function') {
      if(ctx.scriptObj.process.length === 3) {
        // Expects a callback
        flightQueue.push({ctx: ctx, msg: msg});
      }
      else {
        try {
          msg = ctx.scriptObj.process(ctx, msg) || msg;
          ctx.postProcess(ctx, msg);
          messagesProcessed++;
        }
        catch(err) {
          log.error({messageId: 'lib/config/processing-error', err: err, message: msg}, 'Error during message processing.');
        }
      }
    }
  }

  const dateFormat = d3.timeFormat('%Y.%m.%d');
  const REPORT_INTERVAL = 15000;

  setInterval(() => {
    if(!module.exports.config.name)
      return;

    const time = new Date();

    const inputStats = {};

    inputModules.forEach((value, key) => {
      inputStats[key] = (value && value.getStats && value.getStats()) || undefined;
    });

    es.index('logger-stats-' + dateFormat(time), 'logger-stats', {
      "@timestamp": time,
      name: module.exports.config.name,
      worker: cluster.worker.id,
      messagesProcessed: messagesProcessed,
      interval: REPORT_INTERVAL,
      elasticsearch: {
        queued: es.queueLength(),
      },
      inputs: inputStats,
    });

    messagesProcessed = 0;

    //console.log(`Worker ${cluster.worker.id} messages processed: ${messagesProcessed}`);
  }, REPORT_INTERVAL);
}
