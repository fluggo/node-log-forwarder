# node-log-forwarder

Node.js-based log parsing, forwarding, and notifications.

This is a server that provides the functionality of products like
Logstash and Fluentd—it accepts log data from remote sources,
parses them, processes them, and forwards them to notification or
database systems such as Slack, IRC, or Elasticsearch.

But unlike Logstash or Fluentd...

**Processing log entries is done in user-provided scripts written in JavaScript.** Make the processing logic as complex as you need to, and take advantage of any Node.js-compatible library.

A syslog receiver that sends fully-attributed structured syslog to Elasticsearch and messages to IRC channels might look like this:

```javascript
const d3 = require('d3');
const dateFormat = d3.timeFormat('%Y.%m.%d');

function preprocess(ctx, line) {
  return {
    reportingIp: ctx.meta.remoteAddress,
    receivingPort: ctx.meta.localPort,
    receivedTime: ctx.meta.receiveTime,
    eventTime: ctx.meta.receiveTime,
    message: (line instanceof Buffer) ? line.toString('latin1') : line,
    tag: ['raw'],
  };
}

function process(ctx, msg) {
  ctx.sendElasticsearch('raw-syslog-' + dateFormat(msg.eventTime), 'raw-syslog');
  ctx.sendIrc('#syslog');

  if(msg.message.startsWith('ERROR')) {
    msg.tag.push('error');
    ctx.sendIrc('#syslog_errors');
  }

  return { log: msg };
}
```

**Almost any configuration or script change takes effect immediately** without restarting, closing sockets, losing connections, or losing messages. Alter the script above and save it and instantly see the effects of your changes.

It also features very fast startup, and it spreads messages across multiple worker processes for increased throughput on multiprocessor systems.

## Provided inputs

Built-in support for receiving:

* Netflow V9
* UDP (such as syslog)
* Line-based TCP (such as syslog, Bunyan, or custom log formats)

## Provided outputs

Built-in support for sending formatted results to:

* Local files, with filenames supplied by the user script. Use this to structure your log files in directories by source IP, date, both, or whatever other naming scheme you like.
* Elasticsearch, with support for bulk uploads and throughput statistics by worker
* Slack, with full custom formatting
* IRC
* SMTP

# Setup

TODO, but read [config.json.example](./config.json.example)

# Writing a user script

TODO, but see the [sample user scripts](./sample-user-scripts)

# Writing an input module

TODO, but see the [built-in input modules](./inputs)

# Contact, acknowledgements

Written by Brian Crowell, with special thanks to the organization that supported this project, who has asked to remain anonymous.

Please do get in touch if you use this project, I would love to hear about it!
