'use strict';

const cluster = require('cluster');
const config = require('./config.js');
const log = config.log.child({module: 'lib/es'});
const elasticsearch = require('elasticsearch');

var _esClient = null;
var _oldConfig = null;
var _bulkSize = 10 * 1024 * 1024;
const _queue = [];

config.on('change', newConfig => {
  var esConfig = newConfig.elasticsearch;

  var newConfigJson = JSON.stringify(esConfig && esConfig.clientSettings);
  var oldConfigJson = JSON.stringify(_oldConfig && _oldConfig.clientSettings);

  if(newConfigJson !== oldConfigJson) {
    if(_esClient) {
      log.warn({messageId: 'lib/es/closing-connection'}, 'Closing Elasticsearch connection due to new configuration.');
      _esClient.close();
      _esClient = null;
    }
  }

  if(!esConfig || !esConfig.clientSettings)
    return;

  if(!_esClient) {
    (_oldConfig ? log.warn : log.info).call(log, {messageId: 'lib/es/new-connection', config: JSON.parse(newConfigJson)},
      'Creating new Elasticsearch connection due to new configuration.');
    _esClient = new elasticsearch.Client(JSON.parse(newConfigJson));
  }

  _bulkSize = (esConfig.bulkSizeMegabytes * 1024 * 1024) || (10 * 1024 * 1024);
  _oldConfig = esConfig;
});

var _indexInProgress = false;

function push(index, type, doc) {
  // TODO: Could use maps here to save on constructing action strings
  const text = JSON.stringify({index: { _index: index, _type: type }}) + '\n' + JSON.stringify(doc) + '\n';
  _queue.push(text);

  if(!_indexInProgress)
    startIndex();
}

function startIndex() {
  if(!_esClient)
    return;

  //console.log('Starting another index...');

  _indexInProgress = true;

  let count = 0;
  let size = 0;

  while(count < _queue.length) {
    if(size + _queue[count].length > _bulkSize)
      break;

    size += _queue[count].length;
    count++;
  }

  var items = _queue.splice(0, count);

  //console.log(`Indexing ${items.length} items (${_queue.length} remaining)...`);

  _esClient.bulk({body: items.join('')}, (err, result) => {
    if(err) {
      log.warn({messageId: 'lib/es/bulk-load/error', err: err}, 'Elasticsearch bulk load failed.');
      _queue.unshift(...items);
      return startIndex();
    }

    // Check results to know what to retry
    if(result.errors) {
      for(let i = 0; i < items.length; i++) {
        if(result.items[i].index.status === 201)
          continue;

        if(result.items[i].index.status === 429 || result.items[i].index.status === 503) {
          _queue.push(items[i]);
        }
        else {
          log.warn({messageId: 'lib/es/bulk-load/item-error', result: result.items[i], action: items[i]}, 'Item failed for unknown reason.');
        }
      }
    }

    if(_queue.length) {
      return startIndex();
    }
    else {
      _indexInProgress = false;
    }
  });
}

function index(index, type, doc) {
  if(!_esClient)
    return;

  _esClient.index({index: index, type: type, body: doc}, (err, result) => {
    if(err) {
      log.warn({messageId: 'lib/es/index/error', err: err, index: index, type: type, body: doc},
        `Failed to index side document to ${index}/${type}.`);
    }
  });
}

module.exports.push = push;
module.exports.index = index;
module.exports.queueLength = () => _queue.length;
