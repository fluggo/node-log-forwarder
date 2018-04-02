// The msvistalog.js script outputs JSON documents for storing in Elasticsearch. These should be
// compatible with the following Elasticsearch template:

{
  template: 'msvistalog-*',
  settings: {
    'index.codec': 'best_compression',

    // Configure for number of data nodes
    'index.number_of_shards': 2,

    'index.refresh_interval': '10s',

    // Common analyzer
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
    },
  },
  mappings: {
    msvistalog: {
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
        msvistalog: {
          properties: {
            system: {
              properties: {
                provider: {
                  properties: {
                    guid: { type: 'keyword' },    // GUID
                    eventSourceName: { type: 'keyword' },     // string
                  }
                },
                eventId: { type: 'integer' },
                eventType: { type: 'keyword' },   // e.g. AUDIT_FAILURE
                samName: { type: 'keyword' },   // Always uppercase
                severity: { type: 'byte' },
                severityName: { type: 'keyword' },
                version: { type: 'short', index: false },
                task: { type: 'integer' },
                taskName: { type: 'text', fields: { raw: { type: 'keyword' } } },
                opcode: { type: 'integer' },
                opcodeName: { type: 'keyword' },
                recordNumber: { type: 'integer', index: false },
                correlation: {
                  properties: {
                    activityId: { type: 'keyword' },    // GUID
                    relatedActivityId: { type: 'keyword' },   // GUID
                  }
                },
                execution: {
                  properties: {
                    processId: { type: 'integer' },   // unsignedInt, required
                    threadId: { type: 'integer' },    // unsignedInt, required
                  }
                },
                channel: { type: 'keyword' },
                computer: { type: 'keyword' },
              }
            },
            otherFields: { type: 'keyword' },
            unparsedFields: { type: 'keyword' },
            firewall: {
              properties: {
                direction: { type: 'keyword' },
                layer: { type: 'keyword' },
                application: { type: 'keyword' },
                layerRunTimeId: { type: 'integer' },
                filterRunTimeId: { type: 'integer' },

                // 4957
                ruleId: { type: 'keyword' },
                ruleName: { type: 'keyword' },
                ruleAttr: { type: 'keyword' },
                profile: { type: 'keyword' },

                // SIDs
                remoteUserId: { type: 'keyword', copy_to: 'log.all.sid' },
                remoteMachineId: { type: 'keyword', copy_to: 'log.all.sid' },
              }
            },
            logon: {
              properties: {
                // See https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624
                //  Fields headed to common:
                //    SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId
                //    TargetUserSid, TargetUserName, TargetDomainName, TargetLogonId
                //    IpAddress, IpPort -> source.ip, source.port
                logonType: { type: 'byte' },
                logonProcessName: { type: 'keyword' },
                authenticationPackageName: { type: 'keyword' },
                workstationName: { type: 'keyword' },
                logonGuid: { type: 'keyword' },
                keyLength: { type: 'integer' },
                processName: { type: 'keyword' },
                transmittedServices: { type: 'keyword' },
                lmPackageName: { type: 'keyword' },
                processId: { type: 'integer' },
                tokenElevationType: { type: 'keyword' },
                privilege: { type: 'keyword' },

                /*status: { type: 'keyword' },
                subStatus: { type: 'keyword' },*/
                statusCode: { type: 'long' },
                subStatusCode: { type: 'long' },

                impersonationLevel: { type: 'keyword' },

                // Event 4656
                objectServer: { type: 'keyword' },
                objectType: { type: 'keyword' },
                objectName: { type: 'keyword' },
                operationType: { type: 'keyword' },
                transactionId: { type: 'keyword' },
                accessList: { type: 'keyword' },
                propertyList: { type: 'keyword' },

                memberName: { type: 'text', analyzer: 'lowercase' },    // Distinguished name
                memberSid: { type: 'keyword', copy_to: 'log.all.sid' },

                shareName: { type: 'keyword' },
                ticketEncryptionType: { type: 'integer' },
              },
            },
            crypto: {
              properties: {
                keyName: { type: 'keyword' },
                keyType: { type: 'keyword' },
                providerName: { type: 'keyword' },
                algorithmName: { type: 'keyword' },
                module: { type: 'keyword' },
                returnCode: { type: 'long' },
                operation: { type: 'keyword' },
              }
            },
            service: {
              properties: {
                serviceName: { type: 'keyword' },
                state: { type: 'keyword' },
              }
            },
            networkPolicy: {
              properties: {
                proxyPolicyName: { type: 'keyword' },
                networkPolicyName: { type: 'keyword' },
                reasonCode: { type: 'integer' },
                loggingResult: { type: 'keyword' },
                reason: { type: 'keyword' },
                authenticationType: { type: 'keyword' },
                nasIpv4Address: { type: 'ip' },
                calledStationId: { type: 'ip' },
                callingStationId: { type: 'keyword' },
                nasIdentifier: { type: 'keyword' },
                nasPortType: { type: 'keyword' },
                clientName: { type: 'keyword' },
                clientIpAddress: { type: 'ip' },
                authenticationProvider: { type: 'keyword' },
                authenticationServer: { type: 'keyword' },
              }
            }
          }
        }
      }
    }
  },
  aliases: {
    'msvistalog': {},
  },
}