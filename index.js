'use strict';

const config = require('./lib/config.js');
const cluster = require('cluster');

const log = config.log;

if(cluster.isMaster) {
  log.info({messageId: 'master/started'}, 'Starting up master process.');

  cluster.on('fork', worker => {
    checkRunningWorkers();
  });

  cluster.on('disconnect', worker => {
    log.warn({messageId: 'master/worker-disconnected'}, `Worker #${worker.id} (PID ${worker.process.pid}) has disconnected.`);
    checkRunningWorkers();
  });

  cluster.on('exit', worker => {
    log.warn({messageId: 'master/worker-exited'}, `Worker #${worker.id} (PID ${worker.process.pid}) has exited.`);
    checkRunningWorkers();
  });

  function checkRunningWorkers() {
    const targetWorkerCount = config.config.workerCount || 0;
    const workerIds = Object.keys(cluster.workers);

    if(workerIds.length > targetWorkerCount) {
      log.warn({messageId: 'master/too-many-workers'}, `Killing worker to meet worker count.`);
      cluster.workers[workerIds[0]].kill();
    }
    else if(workerIds.length < targetWorkerCount) {
      cluster.fork();
    }
  }

  config.on('change', newConfig => {
    checkRunningWorkers();
  });
}
else {
  log.info({messageId: 'worker/started'}, `Starting up worker process ${cluster.worker.id}.`);
}

