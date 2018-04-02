'use strict';

const cluster = require('cluster');
const config = require('./config.js');
const log = config.log.child({module: 'lib/file'});
const path = require('path');
const fs = require('fs');
const mkdirp = require('mkdirp');

const _writerMap = new Map();

function FileWriter(filePath) {
  this.buffered = [];
  this.open = false;
  this.lastWrite = Date.now();
  this.stream = null;

  // We go ahead and check if everything is in order; for logs that write a lot,
  // this should be an uncommon process, since we won't close a file until it's idle
  // for a long time
  let dirname = path.dirname(filePath);

  mkdirp(dirname, (err, stats) => {
    if(err && err.code !== 'EEXIST') {
      if(err.code === 'EACCES') {
        log.error({messageId: 'lib/file/permission-denied', path: dirname, err:err}, `Permission denied to create directory "${dirname}".`);
      }
      else {
        log.error({messageId: 'lib/file/mkdir-error', path: dirname, err:err}, `Failed to create directory "${dirname}".`);
      }

      // Remove ourselves from the file map so we don't consume memory
      _writerMap.delete(filePath);
      return;
    }

    this.stream = fs.createWriteStream(filePath, {mode: 0o660, flags: 'a'});

    for(let data of this.buffered)
      this.stream.write(data);

    this.buffered = null;

    this.stream.once('open', err => {
      this.open = true;
    });

    this.stream.once('error', err => {
      if(!this.open)
        log.error({messageId: 'lib/file/open-error', path: filePath, err:err}, `Failed to open file "${filePath}".`);
      else
        log.error({messageId: 'lib/file/write-error', file: filePath, err: err}, 'Log write failure.')

      // Remove ourselves from the file map so we don't consume memory
      _writerMap.delete(filePath);
    });
  });
}

FileWriter.prototype.write = function write(data) {
  if(this.buffered)
    this.buffered.push(data);
  else
    this.stream.write(data);

  this.lastWrite = Date.now();
}

FileWriter.prototype.end = function end() {
  if(this.stream) {
    this.stream.end();
  }
}

var basePath = null;
var firstSet = true;

config.on('change', newConfig => {
  var newBasePath = newConfig && newConfig.file && newConfig.file.basePath;

  newBasePath = newBasePath && path.resolve(newBasePath);

  if(newBasePath === basePath)
    return;

  if(newBasePath) {
    basePath = newBasePath;
  }
  else {
    basePath = null;
  }

  (firstSet ? log.info : log.warn).call(log, {messageId: 'lib/file/base-path-set'}, `File log base path changed to "${basePath}".`);
  firstSet = false;
});

function write(filePath, data) {
  if(!basePath) {
    log.warn({messageId: 'lib/file/write/no-base-path'}, `Wanted to write to "${filePath}", but no base path set.`);
    return;
  }

  var newFilePath = path.resolve(basePath, filePath);

  if(!newFilePath.startsWith(basePath)) {
    log.error({messageId: 'lib/file/write/outside-base-path', securityRelevant: true}, `Tried to write to "${filePath}", but it appears to be outside the base path.`);
    return;
  }

  var writer = _writerMap.get(newFilePath);

  if(!writer) {
    writer = new FileWriter(newFilePath);
    _writerMap.set(newFilePath, writer);
  }

  writer.write(data);
}

function clearOldFiles() {
  // Close files that haven't seen any activity in a minute
  const minimumTime = Date.now() - 60 * 1000;
  const oldKeys = [];

  for(let entry of _writerMap.entries()) {
    if(entry[1].lastWrite < minimumTime)
      oldKeys.push(entry[0]);
  }

  for(let key of oldKeys) {
    log.debug({messageId: 'lib/file/clearOldFiles/closing-file', path: key}, `Closing log file "${key}" for inactivity.`);
    _writerMap.get(key).end();
    _writerMap.delete(key);
  }
}

setInterval(clearOldFiles, 1000);

module.exports.write = write;
