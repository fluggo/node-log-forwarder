// The syslog.js script outputs JSON documents for storing in Elasticsearch. These should be
// compatible with the following Elasticsearch template:

{
  template: 'raw-syslog-*',
  settings: {
    //'index.codec': 'best_compression',
    'index.refresh_interval': '10s',

    // Configure the number of shards based on your ES data node count
    'index.number_of_shards': 2,

    analysis: {
      tokenizer: {
        autocomplete_filter: {
          type: "edge_ngram",
          min_gram: 1,
          max_gram: 20,
          token_chars: ["letter", "digit", "punctuation"]
        },
        code_keyword_tokenizer: {
          type: 'pattern',

          // Identifies stretches of non-keywords and numbers
          pattern: '(?:[^a-zA-Z0-9_]++[0-9]*+)++',
        },
      },
      analyzer: {
        lowercase: {
          tokenizer: 'keyword',
          filter: 'lowercase',
        },
        autocomplete: {
          type: "custom",
          tokenizer: "autocomplete_filter",
          filter: ['lowercase'],
        },
        code_keyword: {
          type: 'custom',
          tokenizer: 'code_keyword_tokenizer',
          filter: ['lowercase'],
        },
      },
    }
  },
  mappings: {
    "raw-syslog": {
      include_in_all: false,
      dynamic: false,
      properties: {
        log: {
          properties: {
            recordFinder: {
              type: 'keyword',
            },
            receivingPort: {
              type: 'integer',
            },
            reportingIp: {
              type: 'ip',
            },
            receivedTime: {
              format: 'dateOptionalTime',
              type: 'date'
            },
            eventTime: {
              format: 'dateOptionalTime',
              type: 'date',
            },
            tag: {
              type: 'keyword',
            },
            message: {
              type: 'text',
            },
            ipProtocol: { type: 'byte' },
            all: {
              properties: {
                // Copies of all values set elsewhere
                ip: { type: 'ip' },
                hostname: { type: 'keyword' },
                fqdn: { type: 'keyword' },
                fqdnBreakdown: { type: 'keyword' },
                samName: { type: 'keyword' },   // Always uppercase
                serviceName: { type: 'keyword' },
                sid: { type: 'keyword' },   // Always uppercase
                port: { type: 'integer' },
                domain: { type: 'keyword' },  // Always uppercase
                upn: { type: 'keyword' },   // 
                logonId: { type: 'keyword' },   // 0xHEX
              }
            },
            source: {
              properties: {
                ip: { type: 'ip', copy_to: 'log.all.ip' },
                hostname: { type: 'keyword', copy_to: 'log.all.hostname' },
                fqdn: { type: 'keyword', copy_to: 'log.all.fqdn' },
                fqdnBreakdown: { type: 'keyword', copy_to: 'log.all.fqdnBreakdown' },
                samName: { type: 'keyword', copy_to: 'log.all.samName' },   // Always uppercase
                serviceName: { type: 'keyword', copy_to: 'log.all.serviceName' },
                sid: { type: 'keyword', copy_to: 'log.all.sid' },   // Always uppercase
                port: { type: 'integer', copy_to: 'log.all.port' },
                domain: { type: 'keyword', copy_to: 'log.all.domain' }, // Always uppercase
                upn: { type: 'keyword', copy_to: 'log.all.upn' },   // 
                logonId: { type: 'keyword', copy_to: 'log.all.logonId' },   // 0xHEX
              }
            },
            target: {
              properties: {
                ip: { type: 'ip', copy_to: 'log.all.ip' },
                hostname: { type: 'keyword', copy_to: 'log.all.hostname' },
                fqdn: { type: 'keyword', copy_to: 'log.all.fqdn' },
                fqdnBreakdown: { type: 'keyword', copy_to: 'log.all.fqdnBreakdown' },
                samName: { type: 'keyword', copy_to: 'log.all.samName' },   // Always uppercase
                serviceName: { type: 'keyword', copy_to: 'log.all.serviceName' },
                sid: { type: 'keyword', copy_to: 'log.all.sid' },   // Always uppercase
                port: { type: 'integer', copy_to: 'log.all.port' },
                domain: { type: 'keyword', copy_to: 'log.all.domain' }, // Always uppercase
                upn: { type: 'keyword', copy_to: 'log.all.upn' },   // 
                logonId: { type: 'keyword', copy_to: 'log.all.logonId' },   // 0xHEX
              }
            },
          }
        },
      }
    }
  },
  aliases: {
    "raw-syslog": {},
  }
}
