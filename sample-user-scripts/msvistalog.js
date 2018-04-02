// This script receives Windows event log data from the im_msvistalog
// module of nxlog and uses it to alert operators of security events
// via IRC.
//
// See https://nxlog.co/docs/nxlog-ce/nxlog-reference-manual.html#im_msvistalog

'use strict';

const crypto = require('crypto');
const d3 = require('d3');
const grok = require('node-grok');
const tz = require('timezone/loaded');

const dateFormat = d3.timeFormat('%Y.%m.%d');
const fileDateFormat = d3.timeFormat('%Y-%m-%d');
const localHourFormat = d3.timeFormat('%H');

var _lookupCounter = 1;
var _recordFinderBuffer = Buffer.allocUnsafe(2);

function decodeDNCharacter(value, p1) {
  if(p1.length == 2) {
    return String.fromCharCode(parseInt(p1, 16));
  }
  else {
    return p1;
  }
}

function parseDN(value, options) {
  var options = options || {};

  if(typeof options.decodeValues === 'undefined')
    options.decodeValues = true;

  var result = [];
  var regex = /([^,=]+)=((?:\\[0-9A-Fa-f]{2}|\\.|[^,])+),?/g;
  var match;

  while((match = regex.exec(value)) !== null) {
    result.push({
      type: match[1].toUpperCase(),
      value: options.decodeValues ? match[2].replace(/\\([0-9A-Fa-f]{2}|.)/g, decodeDNCharacter) : match[2]
    });
  }

  return result;
}

function shortenBase64(str) {
  var len = str.length;

  while(len && str[len - 1] === '=')
    len--;

  while(len && str[len - 1] === 'A')
    len--;

  return str.substr(0, len);
}

function makeRecordFinder() {
  if(++_lookupCounter >= 65535)
    _lookupCounter = 1;

  _recordFinderBuffer.writeUInt16LE(_lookupCounter, 0);
  return shortenBase64(_recordFinderBuffer.toString('base64'));
}

function preprocess(ctx, line) {
  return JSON.parse(line);

/*  return {
    reportingIp: ctx.meta.remoteAddress,
    receivingPort: ctx.meta.localPort,
    receivedTime: ctx.meta.receiveTime,
    eventTime: ctx.meta.receiveTime,
    message: (line instanceof Buffer) ? line.toString('utf8') : line,
    tag: ['raw'],
    recordFinder: makeRecordFinder(),
  };*/
}

function uppercase(v) {
  if(!v)
    return v;

  if(Array.isArray(v))
    return v.map(uppercase);

  return v.toUpperCase && v.toUpperCase() || v;
}

function lowercase(v) {
  if(!v)
    return v;

  if(Array.isArray(v))
    return v.map(lowercase);

  return v.toLowerCase && v.toLowerCase() || v;
}

const systemFields = new Set([
  'EventTime',
  'Opcode',
  'OpcodeValue',
  'Hostname',
  'Severity',
  'SeverityValue',
  'EventType',
  'Keywords',
  'EventID',
  'SourceName',
  'ProviderGuid',
  'Version',
  'Task',
  'ProcessID',
  'ThreadID',
  'RecordNumber',
  'Domain',
  'AccountType',
  'AccountName',
  'UserID',
  'Message',
  'Category',
  'Channel',
  'EventReceivedTime',
  'SourceModuleName',
  'SourceModuleType',
  'ActivityID',
  'RelatedActivityID',
  'Keywords_High',
  'Keywords_Low',
]);

const accountChangeAttrs = ['SamAccountName', 'DisplayName', 'UserPrincipalName', 'HomeDirectory', 'HomePath', 'ScriptPath', 'ProfilePath', 'UserWorkstations',
  'PasswordLastSet', 'AccountExpires', 'PrimaryGroupId', 'AllowedToDelegateTo', 'OldUacValue', 'NewUacValue', 'UserAccountControl',
  'UserParameters', 'SidHistory', 'LogonHours', 'DnsHostName', 'ServicePrincipalNames'];

const accessTypeStrings = new Map([
  ['%%1537', 'DELETE'],
  ['%%1538', 'READ_CONTROL'],
  ['%%1539', 'WRITE_DAC'],
  ['%%1540', 'WRITE_OWNER'],
  ['%%1541', 'SYNCHRONIZE'],
  ['%%1542', 'ACCESS_SYS_SEC'],
  ['%%1552', 'Unknown specific access (bit 0)'],
  ['%%1553', 'Unknown specific access (bit 1)'],
  ['%%4416', 'ReadData (or ListDirectory)'],
  ['%%4417', 'WriteData (or AddFile)'],
  ['%%4418', 'AppendData (or AddSubdirectory or CreatePipeInstance)'],
  ['%%4419', 'ReadEA'],
  ['%%4420', 'WriteEA'],
  ['%%4423', 'ReadAttributes'],
  ['%%4424', 'WriteAttributes'],
  ['%%4432', 'Query key value'],
  ['%%4433', 'Set key value'],
  ['%%4434', 'Create sub-key'],
  ['%%4435', 'Enumerate sub-keys'],
  ['%%4436', 'Notify about changes to keys'],
  ['%%4437', 'Create Link'],
  ['%%5378', 'InitializeServer'],
  ['%%5380', 'EnumerateDomains'],
  ['%%5383', 'Undefined Access (no effect) Bit 7'],
  ['%%5394', 'ReadOtherParameters'],
  ['%%5396', 'CreateUser'],
  ['%%5399', 'GetLocalGroupMembership'],
  ['%%5410', 'AddMember'],
  ['%%5412', 'ListMembers'],
  ['%%5415', 'Undefined Access (no effect) Bit 7'],
  ['%%5442', 'WritePreferences'],
  ['%%5444', 'ReadAccount'],
  ['%%5447', 'SetPassword (without knowledge of old password)'],
  ['%%5448', 'ListGroups'],
  ['%%7168', 'Connect to service controller'],
  ['%%7170', 'Enumerate services'],
  ['%%7172', 'Query service database lock state'],
  ['%%7184', 'Query service configuration information'],
  ['%%7185', 'Set service configuration information'],
  ['%%7186', 'Query status of service'],
  ['%%7187', 'Enumerate dependencies of service'],
  ['%%7188', 'Start the service'],
  ['%%7189', 'Stop the service'],
  ['%%7190', 'Pause or continue the service'],
  ['%%7191', 'Query information from service'],
  ['%%7192', 'Issue service-specific control commands'],
  ['%%7680', 'Create Child'],
  ['%%7682', 'List Contents'],
  ['%%7683', 'Write Self'],
  ['%%7684', 'Read Property'],
  ['%%7685', 'Write Property'],
  ['%%7686', 'Delete Tree'],
  ['%%7688', 'Control Access'],
]);

const logonFailureStrings = new Map([
  ['%%2304', 'An Error occured during Logon.'],
  ['%%2306', 'The NetLogon component is not active.'],
  ['%%2307', 'Account locked out.'],
  ['%%2308', 'The user has not been granted the requested logon type at this machine.'],
  ['%%2309', "The specified account's password has expired."],
  ['%%2310', 'Account currently disabled.'],
  ['%%2313', 'Unknown user name or bad password.'],
]);

const impersonationLevelStrings = new Map([
  ['%%1833', 'Impersonation'],
  ['%%1832', 'Identification'],
]);

const keyTypeStrings = new Map([
  ['%%2499', 'Machine key'],
  ['%%2500', 'User key'],
]);

const keyOperationStrings = new Map([
  ['%%2480', 'Open key'],
  ['%%2458', 'Read persisted key from file'],
]);

const tokenElevationTypeStrings = new Map([
  ['%%1936', 'TokenElevationTypeDefault (1)'],
]);

const layerNameStrings = new Map([
  ['%%14597', 'transport'],
  ['%%14601', 'icmp-error'],
  ['%%14608', 'resource-assignment'],
  ['%%14610', 'receive-accept'],
  ['%%14611', 'connect'],
]);

const ipsecStrings = new Map([
  ['%8194', 'Unknown authentication'],
  ['%8199', 'Local computer'],
  ['%8201', 'No state'],
  ['%8206', 'Responder'],
  ['%8217', 'Not enabled'],
  ['%8223', 'AuthIP'],
]);

function dashNull(v) {
  return (!v || v === '-') ? undefined : v;
}

function toNumber(v) {
  if(!v)
    return v;

  if(v.startsWith && v.startsWith('0x'))
    return parseInt(v.substring(2), 16);

  v = +v;
  return isNaN(v) ? undefined : v;
}

function parseIpv4(v) {
  if(!v)
    return v;

  // Convert from IPv6
  if(v === '::')
    return '0.0.0.0';

  if(v.startsWith('::ffff:')) {
    return v.substring(7);
  }

  return v;
}

const xmlEntityLookup = {
  quot: '"',
  amp: '&',
  apos: '\'',
  lt: '<',
  gt: '>'
};

function replaceXmlEntities(v) {
  if(!v || typeof v !== 'string')
    return v;

  return v.replace(/&([a-z]+);/g, (match, p1) => xmlEntityLookup[p1] || '?');
}

function packSecuritySourceTarget(result, line) {
  result.log.source.sid = [dashNull(line.SubjectUserSid), dashNull(line.SubjectMachineSID)].filter(v => v);
  result.log.source.domain = guessSamDomain(line.SubjectDomainName) || guessSamDomain(line.SourceUserName) || guessSamDomain(line.SubjectUserSid) || dashNull(line.SubjectDomainName) || guessSamDomain(line.SubjectMachineSID);

  if(line.SubjectUserName && line.SubjectUserName !== '-') {
    if(line.SubjectUserName.indexOf('@') !== -1) {
      result.log.source.upn = line.SubjectUserName;
    }
    else if(line.SubjectUserName.indexOf('\\') !== -1) {
      result.log.source.samName = line.SubjectUserName;
    }
    else {
      result.log.source.samName = (result.log.source.domain && (result.log.source.domain + '\\') || '') + line.SubjectUserName;
    }
  }

  result.log.source.logonId = line.SubjectLogonId;

  result.log.target.sid = [dashNull(line.TargetSid), dashNull(line.TargetUserSid), dashNull(line.TargetMachineSID)].filter(v => v);
  result.log.target.domain = guessSamDomain(line.TargetDomainName) || guessSamDomain(line.TargetUserName) || guessSamDomain(line.TargetUserSid) || dashNull(line.TargetDomainName) || guessSamDomain(line.TargetMachineSID);

  if(line.TargetUserName && line.TargetUserName !== '-') {
    if(line.TargetUserName.indexOf('@') !== -1) {
      result.log.target.upn = line.TargetUserName;
    }
    else if(line.TargetUserName.indexOf('\\') !== -1) {
      result.log.target.samName = line.TargetUserName;
    }
    else {
      result.log.target.samName = (result.log.target.domain && (result.log.target.domain + '\\') || '') + line.TargetUserName;
    }
  }

  result.log.target.logonId = line.TargetLogonId;
}

function sendToChannelByDomain(ctx, channelBase, domain) {
  ctx.sendIrc(channelBase + (guessSamDomain(domain) || 'other').toLowerCase());
}

function process(ctx, line) {
  // First decode XML on all items
  for(let key of Object.keys(line)) {
    if(!systemFields.has(key)) {
      line[key] = replaceXmlEntities(line[key]);
    }
  }

  var parsedFields = [];

  const result = {
    log: {
      reportingIp: ctx.meta.remoteAddress,
      receivingPort: ctx.meta.localPort,
      receivedTime: ctx.meta.receiveTime,
      eventTime: new Date(line.EventTime),
      message: line.Message,
      protocol: line.Protocol && +line.Protocol,
      all: {
      },
      source: {
      },
      recordFinder: makeRecordFinder(),
      target: {
      },
      tag: new Set(['msvistalog']),
    },
    msvistalog: {
      system: {
        provider: {
          //name: "",   // anyURI
          guid: line.ProviderGuid && line.ProviderGuid.substring(1, line.ProviderGuid.length - 1).toUpperCase(),    // GUID
          eventSourceName: line.SourceName,     // string
        },
        samName: line.Domain && (line.Domain + '\\' + line.AccountName).toUpperCase(),
        eventId: line.EventID,    // array of unsignedShort?
        eventType: line.EventType,  // string (AUDIT_FAILURE, for example)
        severityName: line.Severity,
        severity: line.SeverityValue,
        version: line.Version,    // unsignedByte,
        //level: "value",   // unsignedByte,
        task: line.Task,    // unsignedShort,
        taskName: line.Category,
        opcode: line.OpcodeValue, // unsignedShort
        opcodeName: line.Opcode,  // string
        //recordNumber: line.RecordNumber,    // possibly long! also, don't index
        keywordsLow: line.Keywords_Low,
        keywordsHigh: line.Keywords_High,
        //keywords: line.Keywords,  // hexint64type, don't really know if it's useful
        // timeCreated
        // eventRecordID (array of unsignedLong?)
        correlation: {
          activityId: line.ActivityID && line.ActivityID.substring(1, line.ActivityID.length - 1).toUpperCase(),    // GUID
          relatedActivityId: line.RelatedActivityID && line.RelatedActivityID.substring(1, line.RelatedActivityID.length - 1).toUpperCase(),    // GUID
        },
        execution: {
          processId: line.ProcessID,      // unsignedInt, required
          threadId: line.ThreadID,      // unsignedInt, required
          //processorId: "value",    // unsignedByte
          //sessionId: +line.SessionID,   // unsignedInt
          //kernelTime: "value",    // unsignedInt
          //userTime: "value", // unsignedInt
          //processorTime: "value", // unsignedInt

        },
        channel: line.Channel, // anyURI
        computer: line.Hostname.toLowerCase(), // string, required
/*        security: {
          samName
          //userId: line.UserID, // Supposed to be SID string, but nxlog has a bug
        }*/
        // Anything else
      },
      otherFields: [],
      unparsedFields: [],
      other: {
      }
    }
  };

  // NXlog adds a custom field ERROR_EVT_UNRESOLVED if it can't cope
  if(line.ERROR_EVT_UNRESOLVED) {
    result.log.tag.add('event-unresolved');
  }

  if(result.msvistalog.system.provider.guid === '54849625-5478-4994-A5BA-3E3B0328C30D') {
    // Security
    result.log.tag.add('security');

    if(result.msvistalog.system.eventId === 5152 ||
        result.msvistalog.system.eventId === 5156 ||
        result.msvistalog.system.eventId === 5157 ||
        result.msvistalog.system.eventId === 5158) {
      // Filtering Platform Packet Drop/Accept/Block/Bind
      result.log.tag.add('parsed');
      result.log.tag.add('firewall');

      // Throw away accept messages for now
      if(result.msvistalog.system.eventId === 5156)
        return;

      parsedFields.push('SourceAddress', 'SourcePort', 'DestAddress', 'DestPort', 'Protocol', 'LayerRTID', 'FilterRTID', 'Application', "RemoteUserID", 'RemoteMachineID');

      result.log.source.ip = parseIpv4(line.SourceAddress);
      result.log.source.port = line.SourcePort && +line.SourcePort;
      result.log.target.ip = parseIpv4(line.DestAddress);
      result.log.target.port = line.DestPort && +line.DestPort;
      result.log.protocol = line.Protocol && +line.Protocol;

      result.msvistalog.firewall = {
        layerRunTimeId: line.LayerRTID && +line.LayerRTID,
        filterRunTimeId: line.FilterRTID && +line.FilterRTID,
        application: (line.Application !== '-') ? line.Application : undefined,
        remoteUserId: line.RemoteUserID,
        remoteMachineId: line.RemoteMachineID,
        layer: layerNameStrings.get(line.LayerName) || line.LayerName,
      };

      if(line.Direction) {
        switch(line.Direction) {
          case '%%14592':
            result.msvistalog.firewall.direction = 'inbound';
            break;

          case '%%14593':
            result.msvistalog.firewall.direction = 'outbound';
            break;

          default:
            result.msvistalog.firewall.direction = line.Direction;
            result.log.tag.add('bad-parse');
            break;
        }

        if(result.msvistalog.firewall.direction)
          parsedFields.push('Direction');
      }

      if(line.LayerName) {
        if(result.msvistalog.firewall.layer === line.LayerName)
          result.log.tag.add('bad-parse');
        else
          parsedFields.push('LayerName');
      }
    }
    else if(
        result.msvistalog.system.eventId === 4945 ||
        result.msvistalog.system.eventId === 4946 ||
        result.msvistalog.system.eventId === 4948 ||
        result.msvistalog.system.eventId === 4957) {
      // 4945: Firewall rule listed on startup
      // 4946: Firewall rule added
      // 4948: Firewall rule deleted
      // 4957: Firewall rule not applied
      result.log.tag.add('parsed');
      result.log.tag.add('firewall');

      if(result.msvistalog.system.eventId === 4945 || result.msvistalog.system.eventId === 4957)
        result.log.tag.add('verbose');

      parsedFields.push('RuleId', 'RuleName', 'RuleAttr', 'ProfileChanged', 'ProfileUsed');

      result.msvistalog.firewall = {
        ruleId: line.RuleId,
        ruleName: line.RuleName,
        ruleAttr: line.RuleAttr,
        profile: line.ProfileChanged || line.ProfileUsed,
      };
    }
    else if(
        result.msvistalog.system.eventId === 4954) {
      // 4954: Group policy setting applied; message is pretty much useless
      result.log.tag.add('parsed');
      result.log.tag.add('firewall');
      result.log.tag.add('verbose');
    }
    else if(result.msvistalog.system.eventId === 4616) {
      // System time changed

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="PreviousTime" inType="win:FILETIME" outType="xs:dateTime"/>
          <data name="NewTime" inType="win:FILETIME" outType="xs:dateTime"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'ProcessName');

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        processName: line.ProcessName
      };

      // Temp; send these to the logon channel to see if we can spot crazy things here
      if(line.SubjectUserSid !== 'S-1-5-18') {
        ctx.sendIrc('#infosec_unknown_windows_security_events');
      }
    }
    else if(result.msvistalog.system.eventId === 4985) {
      // State of transaction has changed
      result.log.tag.add('verbose');

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="TransactionId" inType="win:GUID" outType="xs:GUID"/>
          <data name="NewState" inType="win:UInt32" outType="xs:unsignedInt"/>
          <data name="ResourceManager" inType="win:GUID" outType="xs:GUID"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('verbose');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'ProcessName');

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        processName: line.ProcessName
      };
    }
    else if(result.msvistalog.system.eventId === 4611) {
      // 4611: Logon process registered
      // https://technet.microsoft.com/en-us/itpro/windows/keep-secure/event-4611

      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'LogonProcessName');

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        logonProcessName: (line.LogonProcessName === '-') ? undefined : line.LogonProcessName.trim(),
      };

      // Check for known logon process names
      if(result.msvistalog.logon.logonProcessName !== 'Winlogon' &&
          result.msvistalog.logon.logonProcessName !== 'SspTest' &&
          result.msvistalog.logon.logonProcessName !== 'Schannel' &&
          result.msvistalog.logon.logonProcessName !== 'IKE' &&
          result.msvistalog.logon.logonProcessName !== 'IAS' &&
          result.msvistalog.logon.logonProcessName !== 'HTTP.SYS') {
        ctx.sendIrc('#infosec_critical');
      }
    }
    else if(result.msvistalog.system.eventId === 4624) {
      // Logon
      // https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="TargetUserSid" inType="win:SID" outType="xs:string"/>
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="LogonType" inType="win:UInt32" outType="xs:unsignedInt"/>
          <data name="LogonProcessName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="AuthenticationPackageName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="WorkstationName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="LogonGuid" inType="win:GUID" outType="xs:GUID"/>
          <data name="TransmittedServices" inType="win:UnicodeString" outType="xs:string"/>
          <data name="LmPackageName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="KeyLength" inType="win:UInt32" outType="xs:unsignedInt"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */
      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push('IpAddress', 'IpPort',
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'TargetUserSid', 'TargetDomainName', 'TargetUserName', 'TargetLogonId',
        'LogonType', 'LogonProcessName', 'AuthenticationPackageName', 'WorkstationName',
        'LogonGuid', 'TransmittedServices', 'LmPackageName', 'ProcessId', 'ProcessName',
        'KeyLength');

      result.log.source.ip = dashNull(line.IpAddress);
      result.log.source.port = toNumber(dashNull(line.IpPort));

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        logonType: +line.LogonType,
        logonProcessName: (line.LogonProcessName === '-') ? undefined : line.LogonProcessName.trim(),
        authenticationPackageName: dashNull(line.AuthenticationPackageName),
        workstationName: dashNull(line.WorkstationName),
        logonGuid: dashNull(line.LogonGuid),
        transmittedServices: dashNull(line.TransmittedServices),
        lmPackageName: dashNull(line.LmPackageName),
        processId: toNumber(dashNull(line.ProcessId)),
        processName: dashNull(line.ProcessName),
        impersonationLevel: impersonationLevelStrings.get(line.ImpersonationLevel),
        keyLength: dashNull(line.KeyLength),
      };

      if(line.ImpersonationLevel && !result.msvistalog.logon.impersonationLevel)
        result.log.tag.add('bad-parse');

      // Send all non-network and non-service logons to the logon channel
      if(result.msvistalog.logon.logonType !== 3 && result.msvistalog.logon.logonType !== 5) {
        let doIt = true;

        /** redacted code for security reasons */
      }

      // If it's the built-in administrator account...
      if(result.log.target.sid.some(sid => sid.endsWith('-500')))
        ctx.sendIrc('#critical');
    }
    else if(result.msvistalog.system.eventId === 4625) {
      // Account failed to log on
      /*
      <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
        <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
        <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
        <data name="TargetUserSid" inType="win:SID" outType="xs:string"/>
        <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
        <data name="FailureReason" inType="win:UnicodeString" outType="xs:string"/>
        <data name="SubStatus" inType="win:HexInt32" outType="win:HexInt32"/>
        <data name="LogonType" inType="win:UInt32" outType="xs:unsignedInt"/>
        <data name="LogonProcessName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="AuthenticationPackageName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="WorkstationName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="TransmittedServices" inType="win:UnicodeString" outType="xs:string"/>
        <data name="LmPackageName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="KeyLength" inType="win:UInt32" outType="xs:unsignedInt"/>
        <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
        <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
        <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
      </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push('IpAddress', 'IpPort',
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'TargetUserSid', 'TargetDomainName', 'TargetUserName',
        'LogonType', 'LogonProcessName', 'AuthenticationPackageName', 'WorkstationName',
        'LogonGuid', 'TransmittedServices', 'LmPackageName', 'ProcessId', 'ProcessName');

      // Missing Status, FailureReason, Status

      result.log.source.ip = dashNull(line.IpAddress);
      result.log.source.port = toNumber(dashNull(line.IpPort));
      result.log.source.hostname = (!line.WorkstationName || line.WorkstationName === '-') ? undefined : line.WorkstationName.toUpperCase();

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        logonType: +line.LogonType,
        logonProcessName: (!line.LogonProcessName || line.LogonProcessName === '-') ? undefined : line.LogonProcessName.trim(),
        authenticationPackageName: dashNull(line.AuthenticationPackageName),
        workstationName: dashNull(line.WorkstationName),
        logonGuid: dashNull(line.LogonGuid),
        transmittedServices: dashNull(line.TransmittedServices),
        lmPackageName: dashNull(line.LmPackageName),
        processId: toNumber(dashNull(line.ProcessId)),
        processName: dashNull(line.ProcessName),
        statusCode: toNumber(dashNull(line.Status)),
        subStatusCode: toNumber(dashNull(line.SubStatus)),
        failureReason: logonFailureStrings.get(line.FailureReason),
      };

      if(!result.msvistalog.logon.failureReason)
        result.log.tag.add('bad-parse');

      if(line.Status === '0xc000006d') {
        // Send no such user and bad passwords this way
        sendToChannelByDomain(ctx, '#badlogon_', result.log.target.domain);

        ctx.sendIrc('#infosec_bad_passwords');
      }
      else {
        ctx.sendIrc('#infosec_windows_logons');
      }

      if(line.Status === '0xc000015b') {
        // STATUS_LOGON_TYPE_NOT_GRANTED
        ctx.sendIrc('#infosec_interesting');
        ctx.sendSlack('#infosec_interesting');
      }

      // If it's the built-in administrator account...
      ctx.meta.targetArticle = getArticle(ctx, {samName: result.log.target.samName, sid: result.log.target.sid});

      ctx.meta.enterpriseAdmin = ctx.meta.targetArticle && ctx.meta.targetArticle.tags.has('enterprise-admin');
      ctx.meta.domainAdmin = ctx.meta.targetArticle && ctx.meta.targetArticle.tags.has('domain-admin');
      ctx.meta.builtinAdmin = first(result.log.target.sid).endsWith('-500') || (ctx.meta.targetArticle && ctx.meta.targetArticle.sid && first(ctx.meta.targetArticle.sid).endsWith('-500'));
      ctx.meta.neverLogon = ctx.meta.targetArticle && ctx.meta.targetArticle.tags.has('never-logon');

      if(ctx.meta.enterpriseAdmin)
        result.log.tag.add('enterprise-admin');

      if(ctx.meta.domainAdmin)
        result.log.tag.add('domain-admin');

      if(ctx.meta.builtinAdmin)
        result.log.tag.add('builtin-admin');

      if(ctx.meta.neverLogon)
        result.log.tag.add('never-logon');

      ctx.meta.sourceMachineArticle = getArticle(ctx, {ip: result.log.source.ip});
      ctx.meta.fromDC = ctx.meta.sourceMachineArticle && ctx.meta.sourceMachineArticle.tags.has('domain-controller');

      if(ctx.meta.fromDC && guessFqdnDomain(ctx.meta.sourceMachineArticle.samName) === guessFqdnDomain(line.TargetDomainName)) {
        // Ignore
      }
      else if(ctx.meta.neverLogon) {
        ctx.sendSlack('#infosec_critical');
      }
      else if(ctx.meta.builtinAdmin || ctx.meta.enterpriseAdmin || ctx.meta.domainAdmin) {
        //   0xc00002ee/0x0 STATUS_UNFINISHED_CONTEXT_DELETED
        //   0xc000005e/0x0 STATUS_NO_LOGON_SERVERS
        //   0xc000006d/(several) STATUS_LOGON_FAILURE
        //      0xc0000064 STATUS_NO_SUCH_USER
        //      0xc000006a STATUS_WRONG_PASSWORD
        //   0xc000006e/(several) STATUS_ACCOUNT_RESTRICTION
        //      0xc0000071 STATUS_PASSWORD_EXPIRED
        //      0xc0000072 STATUS_ACCOUNT_DISABLED
        //      0xc000006f STATUS_INVALID_LOGON_HOURS
        //   0xc0000224/0x0 STATUS_PASSWORD_MUST_CHANGE
        //   0xc000015b/0x0 STATUS_LOGON_TYPE_NOT_GRANTED
        //   0xc0000234/0x0 STATUS_ACCOUNT_LOCKED_OUT
        //   0xc0000017/0x0 STATUS_NO_MEMORY
        //   0xc0000192/0x0 STATUS_NETLOGON_NOT_STARTED
        //   0xc0000133/0x0 STATUS_TIME_DIFFERENCE_AT_DC
        //   0xc000018d/0x0 STATUS_TRUSTED_RELATIONSHIP_FAILURE
        //   0xc00000dc/0x0 STATUS_INVALID_SERVER_STATE

        if(line.Status === '0xc00002ee') {
          // Abandoned logons are uninteresting
        }
        else if(line.Status === '0xc0000192') {
          // Early netlogon failures are uninteresting
        }
        else if(line.Status === '0xc000005e') {
          // No logon servers available is uninteresting
        }
        else if(line.Status === '0xc000006d' || line.Status === '0xc000006e' || line.Status === '0xc000015b') {
          ctx.sendSlack('#infosec_critical');
          result.log.tag.add('critical');
        }
        else {
          ctx.sendSlack('#infosec_interesting');
          result.log.tag.add('interesting');
        }
      }
    }
    else if(result.msvistalog.system.eventId === 4634) {
      // Logoff

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="TargetUserSid" inType="win:SID" outType="xs:string"/>
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="LogonType" inType="win:UInt32" outType="xs:unsignedInt"/>
        </template>
      */
      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push(
        'TargetUserSid', 'TargetDomainName', 'TargetUserName', 'TargetLogonId',
        'LogonType');

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        logonType: +line.LogonType,
      };
    }
    else if(result.msvistalog.system.eventId === 4672) {
      // Special privileges ("Special logon")

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="PrivilegeList" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'PrivilegeList');

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        privilege: line.PrivilegeList.trim().split(/\s+/g),
      };
    }
    else if(result.msvistalog.system.eventId === 4648) {
      // Logon with explicit credentials

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="LogonGuid" inType="win:GUID" outType="xs:GUID"/>
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetLogonGuid" inType="win:GUID" outType="xs:GUID"/>
          <data name="TargetServerName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetInfo" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'TargetUserSid', 'TargetDomainName', 'TargetUserName', 'TargetLogonId',
        'IpAddress', 'IpPort', 'LogonGuid', 'ProcessId', 'ProcessName');

      result.log.source.ip = dashNull(line.IpAddress);
      result.log.source.port = toNumber(dashNull(line.IpPort));

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        logonGuid: dashNull(line.LogonGuid),
        processId: toNumber(dashNull(line.ProcessId)),
        processName: dashNull(line.ProcessName),
      };

      if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        ctx.sendIrc('#infosec_windows_logons');
      }

      // If it's the built-in administrator account...
      if(result.log.target.sid.some(sid => sid.endsWith('-500')))
        ctx.sendIrc('#infosec_critical');
    }
    else if(result.msvistalog.system.eventId === 4768) {
      // Kerberos TGT requested

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetSid" inType="win:SID" outType="xs:string"/>
          <data name="ServiceName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ServiceSid" inType="win:SID" outType="xs:string"/>
          <data name="TicketOptions" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="TicketEncryptionType" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="PreAuthType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
          <data name="CertIssuerName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="CertSerialNumber" inType="win:UnicodeString" outType="xs:string"/>
          <data name="CertThumbprint" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push(
        'TargetUserName', 'TargetDomainName', 'TargetSid', 'IpAddress', 'IpPort', 'Status',
        'ServiceName', 'ServiceSid');

      result.log.source.ip = parseIpv4(dashNull(line.IpAddress));
      result.log.source.port = toNumber(dashNull(line.IpPort));
      result.log.source.sid = dashNull(line.TargetSid);

      const targetDomain = guessFqdnDomain(line.TargetDomainName);

      result.log.source.upn = line.TargetUserName.toLowerCase() + '@' + (targetDomain || line.TargetDomainName);
      result.log.source.domain = guessSamDomain(line.TargetDomainName) || line.TargetDomainName;

      result.log.target.serviceName = dashNull(line.ServiceName);
      result.log.target.sid = dashNull(line.ServiceSid);

      result.msvistalog.logon = {
        statusCode: toNumber(dashNull(line.Status)),
        ticketEncryptionType: (line.TicketEncryptionType === '0xffffffff') ? undefined : toNumber(line.TicketEncryptionType),
      };

      ctx.meta.sourceArticle = getArticle(ctx, {sid: result.log.source.sid, samName: (guessSamDomain(line.TargetDomainName) || line.TargetDomainName) + '\\' + line.TargetUserName});

      ctx.meta.enterpriseAdmin = ctx.meta.sourceArticle && ctx.meta.sourceArticle.tags.has('enterprise-admin');
      ctx.meta.domainAdmin = ctx.meta.sourceArticle && ctx.meta.sourceArticle.tags.has('domain-admin');
      ctx.meta.builtinAdmin = first(result.log.source.sid).endsWith('-500') || (ctx.meta.sourceArticle && ctx.meta.sourceArticle.sid && first(ctx.meta.sourceArticle.sid).endsWith('-500'));
      ctx.meta.neverLogon = ctx.meta.sourceArticle && ctx.meta.sourceArticle.tags.has('never-logon');

      ctx.meta.sourceMachineArticle = getArticle(ctx, {ip: result.log.source.ip});
      ctx.meta.fromDC = ctx.meta.sourceMachineArticle && ctx.meta.sourceMachineArticle.tags.has('domain-controller');

      if(ctx.meta.enterpriseAdmin)
        result.log.tag.add('enterprise-admin');

      if(ctx.meta.domainAdmin)
        result.log.tag.add('domain-admin');

      if(ctx.meta.builtinAdmin)
        result.log.tag.add('builtin-admin');

      if(ctx.meta.neverLogon)
        result.log.tag.add('never-logon');

      if(ctx.meta.fromDC && guessFqdnDomain(ctx.meta.sourceMachineArticle.samName) === guessFqdnDomain(line.TargetDomainName)) {
        // Ignore
      }
      else if(ctx.meta.neverLogon) {
        ctx.sendSlack('#infosec_critical');
      }
      else if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        if(ctx.meta.builtinAdmin || ctx.meta.enterpriseAdmin || ctx.meta.domainAdmin) {
          // https://www.ietf.org/rfc/rfc4120.txt
          // KDC_ERR_PREAUTH_FAILED 0x18 (bad password)*
          // KDC_ERR_KEY_EXPIRED 0x17 (password expired)
          // KDC_ERR_CLIENT_REVOKED 0x12 (disabled user)*
          // KDC_ERR_C_PRINCIPAL_UNKNOWN 0x6 (unknown user)
          // KRB_AP_ERR_SKEW 37 (clock skew created)

          if(result.msvistalog.logon.statusCode === 24 || result.msvistalog.logon.statusCode === 18) {
            ctx.sendSlack('#infosec_critical');
            result.log.tag.add('critical');
          }
          else {
            ctx.sendSlack('#infosec_interesting');
            result.log.tag.add('interesting');
          }
        }
        else {
          if(result.msvistalog.logon.statusCode === 0x17 || result.msvistalog.logon.statusCode === 0x18 || result.msvistalog.logon.statusCode === 0x6) {
            // Send expired and bad passwords this way
            sendToChannelByDomain(ctx, '#badlogon_', result.log.target.domain);

            ctx.sendIrc('#infosec_bad_passwords');
          }
          else {
            ctx.sendIrc('#infosec_windows_logons');
          }
        }
      }
    }
    else if(result.msvistalog.system.eventId === 4769) {
      // Kerberos service ticket requested

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">\
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ServiceName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ServiceSid" inType="win:SID" outType="xs:string"/>
          <data name="TicketOptions" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="TicketEncryptionType" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
          <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="LogonGuid" inType="win:GUID" outType="xs:GUID"/>
          <data name="TransmittedServices" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push(
        'TargetUserName', 'TargetDomainName', 'IpAddress', 'IpPort', 'LogonGuid', 'TransmittedServices', 'Status',
        'ServiceName', 'ServiceSid', 'TicketEncryptionType');

      result.log.source.ip = parseIpv4(dashNull(line.IpAddress));
      result.log.source.port = toNumber(dashNull(line.IpPort));
      result.log.source.upn = dashNull(line.TargetUserName && line.TargetUserName.toLowerCase());
      result.log.source.domain = dashNull(line.TargetDomainName);
      result.log.target.serviceName = dashNull(line.ServiceName);
      result.log.target.sid = dashNull(line.ServiceSid)

      result.msvistalog.logon = {
        logonGuid: dashNull(line.LogonGuid),
        transmittedServices: dashNull(line.TransmittedServices),
        statusCode: toNumber(dashNull(line.Status)),
        ticketEncryptionType: (line.TicketEncryptionType === '0xffffffff') ? undefined : toNumber(line.TicketEncryptionType),
      };

      if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        // Audit failures, but ignore KDC_ERR_MUST_USE_USER2USER (0x1b); not quite sure what the issue is there,
        // see http://arstechnica.com/civis/viewtopic.php?t=1232451 and https://blogs.technet.microsoft.com/mrsnrub/2010/03/25/you-u2u-me-too/

        // Also ignore 0x20 KRB_AP_ERR_TKT_EXPIRED, because the event doesn't really carry useful information

        if(result.msvistalog.logon.statusCode === 0x1b) {
          result.log.tag.add('verbose');
          ctx.sendIrc('#annoying')
        }
        else if(result.msvistalog.logon.statusCode !== 0x20) {
          result.log.tag.add('verbose');
          ctx.sendIrc('#infosec_windows_logons');
        }
      }
    }
    else if(result.msvistalog.system.eventId === 4770) {
      // Kerberos service ticket renewed

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ServiceName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ServiceSid" inType="win:SID" outType="xs:string"/>
          <data name="TicketOptions" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="TicketEncryptionType" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('logon');
      result.log.tag.add('verbose');

      parsedFields.push(
        'TargetUserName', 'TargetDomainName', 'IpAddress', 'IpPort',
        'ServiceName', 'ServiceSid');

      result.log.source.ip = parseIpv4(dashNull(line.IpAddress));
      result.log.source.port = toNumber(dashNull(line.IpPort));
      result.log.target.serviceName = dashNull(line.ServiceName);
      result.log.target.sid = dashNull(line.ServiceSid)

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        ticketEncryptionType: (line.TicketEncryptionType === '0xffffffff') ? undefined : toNumber(line.TicketEncryptionType),
      };

      if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        ctx.sendIrc('#infosec_windows_logons');
      }
    }
    else if(result.msvistalog.system.eventId === 4647) {
      // User initiated logoff

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="TargetUserSid" inType="win:SID" outType="xs:string"/>
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push(
        'TargetUserSid', 'TargetDomainName', 'TargetUserName', 'TargetLogonId');

      packSecuritySourceTarget(result, line);

      // Logoffs are interesting
      ctx.sendIrc('#infosec_windows_logons');
    }
    else if(result.msvistalog.system.eventId === 4771) {
      // Kerberos pre-auth failed

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetSid" inType="win:SID" outType="xs:string"/>
          <data name="ServiceName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TicketOptions" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="PreAuthType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
          <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
          <data name="CertIssuerName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="CertSerialNumber" inType="win:UnicodeString" outType="xs:string"/>
          <data name="CertThumbprint" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('logon');

      parsedFields.push(
        'TargetUserName', 'TargetSid', 'IpAddress', 'IpPort', 'Status',
        'ServiceName');

      result.log.source.ip = parseIpv4(dashNull(line.IpAddress));
      result.log.source.port = toNumber(dashNull(line.IpPort));

      result.log.target.sid = dashNull(line.TargetSid);
      result.log.target.domain = guessSamDomain(line.ServiceName);
      result.log.target.samName = (line.TargetUserName !== '-') ? ((result.log.target.domain ? (result.log.target.domain + '\\') : '') + line.TargetUserName) : undefined;
      result.log.target.serviceName = dashNull(line.ServiceName);

      result.msvistalog.logon = {
        statusCode: toNumber(dashNull(line.Status)),
      };

      if(result.msvistalog.logon.statusCode === 0x17 || result.msvistalog.logon.statusCode === 0x18) {
        // Send expired and bad passwords this way
        sendToChannelByDomain(ctx, '#badlogon_', result.log.target.domain || result.log.target.serviceName);

        ctx.sendIrc('#infosec_bad_passwords');
      }
      else
        ctx.sendIrc('#infosec_windows_logons');

      ctx.meta.targetArticle = getArticle(ctx, {sid: result.log.target.sid});

      ctx.meta.enterpriseAdmin = ctx.meta.targetArticle && ctx.meta.targetArticle.tags.has('enterprise-admin');
      ctx.meta.domainAdmin = ctx.meta.targetArticle && ctx.meta.targetArticle.tags.has('domain-admin');
      ctx.meta.builtinAdmin = first(result.log.target.sid).endsWith('-500') || (ctx.meta.targetArticle && ctx.meta.targetArticle.sid && first(ctx.meta.targetArticle.sid).endsWith('-500'));
      ctx.meta.neverLogon = ctx.meta.targetArticle && ctx.meta.targetArticle.tags.has('never-logon');

      ctx.meta.sourceMachineArticle = getArticle(ctx, {ip: result.log.source.ip});
      ctx.meta.fromDC = ctx.meta.sourceMachineArticle && ctx.meta.sourceMachineArticle.tags.has('domain-controller');

      if(ctx.meta.enterpriseAdmin)
        result.log.tag.add('enterprise-admin');

      if(ctx.meta.domainAdmin)
        result.log.tag.add('domain-admin');

      if(ctx.meta.builtinAdmin)
        result.log.tag.add('builtin-admin');

      if(ctx.meta.neverLogon)
        result.log.tag.add('never-logon');

      if(ctx.meta.fromDC && guessSamDomain(ctx.meta.sourceMachineArticle.samName) === result.log.target.domain) {
        // Ignore
      }
      else if(ctx.meta.neverLogon) {
        ctx.sendSlack('#infosec_critical');
        result.log.tag.add('critical');
      }
      else if(ctx.meta.builtinAdmin || ctx.meta.enterpriseAdmin || ctx.meta.domainAdmin) {
        // https://www.ietf.org/rfc/rfc4120.txt
        // KDC_ERR_PREAUTH_FAILED 0x18 (bad password)*
        // KDC_ERR_KEY_EXPIRED 0x17 (password expired)
        // KDC_ERR_CLIENT_REVOKED 0x12 (disabled user)*
        // KDC_ERR_C_PRINCIPAL_UNKNOWN (unknown user)
        // KRB_AP_ERR_SKEW 37 (clock skew created)

        if(result.msvistalog.logon.statusCode === 24 || result.msvistalog.logon.statusCode === 18) {
          ctx.sendSlack('#infosec_critical');
          result.log.tag.add('critical');
        }
        else {
          ctx.sendSlack('#infosec_interesting');
          result.log.tag.add('interesting');
        }
      }
    }
    else if(
        result.msvistalog.system.eventId === 5056 ||
        result.msvistalog.system.eventId === 5061 ||
        result.msvistalog.system.eventId === 5058) {
      // 5056: Crypto self-test
      // 5061: Crypto operation
      // 5058: Key file operation

      result.log.tag.add('parsed');
      result.log.tag.add('verbose');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'AlgorithmName', 'KeyName', 'KeyType', 'Operation', 'ReturnCode', 'ProviderName', 'Module'
        );

      packSecuritySourceTarget(result, line);

      result.msvistalog.crypto = {
        keyName: line.KeyName && line.KeyName.toUpperCase(),
        keyType: keyTypeStrings.get(line.KeyType),
        algorithmName: line.AlgorithmName,
        module: line.Module,
        returnCode: toNumber(line.ReturnCode),
        operation: line.Operation && keyOperationStrings.get(line.Operation),
        providerName: line.ProviderName,
      };

      if((line.KeyName && !result.msvistalog.crypto.keyType) ||
          (line.Operation && !result.msvistalog.crypto.operation))
        result.log.tag.add('bad-parse');
    }
    else if(result.msvistalog.system.eventId === 4661) {
      // 4661: SAM Handle to object requested
      // Flat out ignore
      return null;
    }
    else if(result.msvistalog.system.eventId === 4653) {
      // IPsec main mode negotiation failed
      // So far as I know, we're not using IPsec internally; why it's even on, I don't know
      result.log.tag.add('ipsec');
      result.log.tag.add('parsed');

      parsedFields.push('LocalAddress', 'LocalKeyModPort', 'RemoteAddress', 'RemoteKeyModPort');

      result.log.target.ip = line.LocalAddress;
      result.log.target.port = line.LocalKeyModPort;
      result.log.source.ip = line.RemoteAddress;
      result.log.source.port = line.RemoteKeyModPort;

      if(line.LocalMMPrincipalName !== '-' || line.RemoteMMPrincipalName !== '-' ||
          line.FailureReason !== 'No policy configured')
        ctx.sendIrc('#infosec_unknown_windows_security_events');
    }
    else if(result.msvistalog.system.eventId === 4656 ||
        result.msvistalog.system.eventId === 4663) {
      // 4656: Handle to object requested
      // 4663: An attempt was made to access an object

      if(result.msvistalog.system.eventId === 4656 &&
          line.ProcessName === 'C:\\Program Files\\Epilog\\Epilog.exe' &&
          line.ObjectName === 'C:\\Windows\\System32\\dhcp') {
        // SPAM
        return null;
      }

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="ObjectServer" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ObjectType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ObjectName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="HandleId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="TransactionId" inType="win:GUID" outType="xs:GUID"/>
          <data name="AccessList" inType="win:UnicodeString" outType="xs:string"/>
          <data name="AccessReason" inType="win:UnicodeString" outType="xs:string"/>
          <data name="AccessMask" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="PrivilegeList" inType="win:UnicodeString" outType="xs:string"/>
          <data name="RestrictedSidCount" inType="win:UInt32" outType="xs:unsignedInt"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('verbose');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'ObjectServer', 'ObjectType', 'ObjectName', 'TransactionId', 'AccessList', 'ProcessName'
        );

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        processId: toNumber(dashNull(line.NewProcessId)),
        processName: dashNull(line.NewProcessName),
        objectServer: line.ObjectServer,
        objectType: line.ObjectType,
        objectName: line.ObjectName,
        transactionId: line.TransactionId && line.TransactionId.substring(1, line.TransactionId.length - 1).toUpperCase(),
        accessList: line.AccessList && line.AccessList.trim().split(/\s+/g).map(v => {
          const type = accessTypeStrings.get(v);

          if(!type && !v.startsWith('{'))
            result.log.tag.add('bad-parse');

          return type || v;
        }),
      };

      /*if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        ctx.sendIrc('#infosec_general_failures');
      }*/
    }
    else if(result.msvistalog.system.eventId === 4658) {
      // 4658: Handle to object closed

      // Holy hell, just turn the damn thing off
      return null;
/*      result.log.tag.add('parsed');

      if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        ctx.sendIrc('#infosec_general_failures');
      }*/
    }
    else if(result.msvistalog.system.eventId === 4662) {
      // Directory service: operation was performed

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="ObjectServer" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ObjectType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ObjectName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="OperationType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="HandleId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="AccessList" inType="win:UnicodeString" outType="xs:string"/>
          <data name="AccessMask" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="Properties" inType="win:UnicodeString" outType="xs:string"/>
          <data name="AdditionalInfo" inType="win:UnicodeString" outType="xs:string"/>
          <data name="AdditionalInfo2" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('active-directory');

      parsedFields.push('SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId',
        'ObjectServer', 'ObjectType', 'ObjectName', 'OperationType', 'Properties'
        );

      // Missing HandleId, AccessMask, AdditionalInfo, AdditionalInfo2

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        objectServer: line.ObjectServer,
        objectType: line.ObjectType,
        objectName: line.ObjectName,
        operationType: line.OperationType,
        accessList: line.AccessList.trim().split(/\t*\r?\n\t*/g).filter(v => v !== '-' && v !== '---').map(v => {
          const type = accessTypeStrings.get(v);

          if(!type && v.startsWith('%'))
            result.log.tag.add('bad-parse');

          return type || v;
        }),
        propertyList: line.Properties.trim().split(/\t*\r?\n\t*/g).filter(v => v !== '-' && v !== '---').map(v => {
          const type = accessTypeStrings.get(v);

          if(!type && v.startsWith('%'))
            result.log.tag.add('bad-parse');

          return type || v;
        }),
      };

      if(result.msvistalog.logon.accessList.indexOf('Create Child') !== -1) {
        ctx.sendIrc('#infosec_ad_changes');
      }
    }
    else if(result.msvistalog.system.eventId === 4688) {
      // New process created

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="NewProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="NewProcessName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TokenElevationType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('process');

      parsedFields.push('SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId',
        'NewProcessId', 'NewProcessName', 'TokenElevationType'
        );

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        processId: toNumber(dashNull(line.NewProcessId)),
        processName: dashNull(line.NewProcessName),
        tokenElevationType: tokenElevationTypeStrings.get(line.TokenElevationType),
      };

      if(!result.msvistalog.logon.tokenElevationType)
        result.log.tag.add('bad-parse');

      if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        ctx.sendIrc('#infosec_general_failures');
      }
    }
    else if(result.msvistalog.system.eventId === 4689) {
      // Process has exited

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('process');

      parsedFields.push('SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId',
        'Status', 'ProcessName');

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        //processId: toNumber(dashNull(line.NewProcessId)),
        processName: dashNull(line.ProcessName),
        statusCode: toNumber(dashNull(line.Status)),
      };

      if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        ctx.sendIrc('#infosec_general_failures');
      }
    }
    else if(result.msvistalog.system.eventId === 4693) {
      // 4693: Recovery of data protection master key was attempted
      // Microsoft guidelines suggest this event isn't much worth monitoring, see https://technet.microsoft.com/en-us/itpro/windows/keep-secure/event-4693

      result.log.tag.add('parsed');
      result.log.tag.add('verbose');

      parsedFields.push('SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId');

      packSecuritySourceTarget(result, line);
    }
    else if(result.msvistalog.system.eventId === 4698 ||
      result.msvistalog.system.eventId === 4699 ||
      result.msvistalog.system.eventId === 4700 ||
      result.msvistalog.system.eventId === 4701 ||
      result.msvistalog.system.eventId === 4702) {
      // 4698: Scheduled task was created
      // 4699: Scheduled task was deleted
      // 4700: Scheduled task was enabled
      // 4701: Scheduled task was disabled
      // 4702: Scheduled task was updated
      result.log.tag.add('parsed');

      parsedFields.push('SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId');

      packSecuritySourceTarget(result, line);

      if(line.TaskName !== '\\Microsoft\\Windows\\Customer Experience Improvement Program\\Server\\ServerCeipAssistant')
        ctx.sendIrc('#infosec_critical');
    }
    else if(result.msvistalog.system.eventId === 4673) {
      // Sensitive privilege use

      result.log.tag.add('parsed');
      result.log.tag.add('verbose');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'ObjectServer', 'Service', 'PrivilegeList', 'ProcessName'
        );

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        objectServer: line.ObjectServer,
        privilege: line.PrivilegeList.trim().split(/\s+/g),
        processName: line.ProcessName,
      };

      result.msvistalog.service = {
        serviceName: dashNull(line.Service),
      };
    }
    else if(
        result.msvistalog.system.eventId === 4720 ||
        result.msvistalog.system.eventId === 4722 ||
        result.msvistalog.system.eventId === 4723 ||
        result.msvistalog.system.eventId === 4724 ||
        result.msvistalog.system.eventId === 4725 ||
        result.msvistalog.system.eventId === 4726 ||
        result.msvistalog.system.eventId === 4738 ||
        result.msvistalog.system.eventId === 4740 ||
        result.msvistalog.system.eventId === 4741 ||
        result.msvistalog.system.eventId === 4742 ||
        result.msvistalog.system.eventId === 4743 ||
        result.msvistalog.system.eventId === 4767) {
      // 4720: Create acccount
      // 4722: Enable account
      // 4723: Change password
      // 4724: Reset password
      // 4725: Disable account
      // 4726: Delete account
      // 4738: User account changed
      // 4740: User account locked out
      // 4741: Computer account created
      // 4742: Computer account changed
      // 4743: Computer account deleted
      // 4767: Account unlocked

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="TargetSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
        </template>
      */

      // Some of these have PrivilegeList

      result.log.tag.add('parsed');
      result.log.tag.add('accounts');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'TargetUserName', 'TargetDomainName', 'TargetSid'
        );

      packSecuritySourceTarget(result, line);

      if(result.msvistalog.system.eventId === 4740) {
        // "Account locked out" places the workstation's name in the TargetDomainName field
        result.log.target.samName = line.SubjectDomainName + '\\' + line.TargetUserName;
        result.log.target.hostname = line.TargetDomainName;

        ctx.sendIrc('#lockouts');
      }
      else if(result.msvistalog.system.eventId === 4767) {
        // "Account unlocked"
        ctx.sendIrc('#lockouts');
      }
      else if(result.msvistalog.system.eventId === 4742 || result.msvistalog.system.eventId === 4738) {
        const setAttrs = accountChangeAttrs.filter(attr => line[attr] !== '-' && line[attr] !== undefined);
        const attrSet = new Set(setAttrs);

        // Some special cases
        if(attrSet.size === 1 && attrSet.has('PasswordLastSet') &&
          result.log.source.samName.toUpperCase() === 'NT AUTHORITY\\ANONYMOUS LOGON') {

          // Something changed its own password; ignore this
        }
        else if(result.msvistalog.system.eventId === 4742 &&
          result.log.source.samName.toUpperCase() === result.log.target.samName.toUpperCase() &&
          !setAttrs.some(attr => attr !== 'DnsHostName' && attr !== 'ServicePrincipalNames')) {

          // Computers will set their own DnsHostName and ServicePrincipalNames attributes, this is normal
          result.log.tag.add('verbose');
        }
        else {
          ctx.sendIrc('#infosec_accounts');
        }
      }
      else if(result.msvistalog.system.eventId !== 4723) {
        if(result.msvistalog.system.eventId === 4724 || result.msvistalog.system.eventId === 4738) {
          // Go ahead and note password resets in the lockouts channel
          ctx.sendIrc('#lockouts');
        }

        ctx.sendIrc('#infosec_accounts');
      }
    }
    else if(
        result.msvistalog.system.eventId === 4727 ||
        result.msvistalog.system.eventId === 4728 ||
        result.msvistalog.system.eventId === 4729 ||
        result.msvistalog.system.eventId === 4730 ||
        result.msvistalog.system.eventId === 4731 ||
        result.msvistalog.system.eventId === 4732 ||
        result.msvistalog.system.eventId === 4733 ||
        result.msvistalog.system.eventId === 4734 ||
        result.msvistalog.system.eventId === 4735 ||
        result.msvistalog.system.eventId === 4737 ||
        result.msvistalog.system.eventId === 4744 ||
        result.msvistalog.system.eventId === 4745 ||
        result.msvistalog.system.eventId === 4746 ||
        result.msvistalog.system.eventId === 4747 ||
        result.msvistalog.system.eventId === 4748 ||
        result.msvistalog.system.eventId === 4749 ||
        result.msvistalog.system.eventId === 4750 ||
        result.msvistalog.system.eventId === 4751 ||
        result.msvistalog.system.eventId === 4752 ||
        result.msvistalog.system.eventId === 4753 ||
        result.msvistalog.system.eventId === 4754 ||
        result.msvistalog.system.eventId === 4755 ||
        result.msvistalog.system.eventId === 4756 ||
        result.msvistalog.system.eventId === 4757 ||
        result.msvistalog.system.eventId === 4758 ||
        result.msvistalog.system.eventId === 4759 ||
        result.msvistalog.system.eventId === 4760 ||
        result.msvistalog.system.eventId === 4761 ||
        result.msvistalog.system.eventId === 4762 ||
        result.msvistalog.system.eventId === 4763 ||
        result.msvistalog.system.eventId === 4764 ||
        result.msvistalog.system.eventId === 4765 ||
        result.msvistalog.system.eventId === 4766 ||
        result.msvistalog.system.eventId === 4781 ||
        result.msvistalog.system.eventId === 4782) {

      // 4727: Global security group created
      // 4728: Global security group member added
      // 4729: Global security group member removed
      // 4730: Global security group deleted
      // 4731: Local security group created
      // 4732: Local security group member added
      // 4733: Local security group member removed
      // 4734: Local security group deleted
      // 4735: Local security group changed
      // 4737: Global security group changed
      // 4744: Local non-security group created
      // 4745: Local non-security group changed
      // 4746: Local non-security group member added
      // 4747: Local non-security group member removed
      // 4748: Local non-security group deleted
      // 4749: Global non-security group created
      // 4750: Global non-security group changed
      // 4751: Global non-security group member added
      // 4752: Global non-security group member removed
      // 4753: Global non-security group deleted
      // 4754: Universal security group created
      // 4755: Universal security group changed
      // 4756: Universal security group member added
      // 4757: Universal security group member removed
      // 4758: Universal security group deleted
      // 4759: Universal non-security group created
      // 4760: Universal non-security group changed
      // 4761: Universal non-security group member added
      // 4762: Universal non-security group member removed
      // 4763: Universal non-security group deleted
      // 4764: Group's type changed
      // 4765: SID history added
      // 4766: SID history failed
      // 4781: Account name changed
      // 4782: Password hash accessed

      result.log.tag.add('parsed');
      result.log.tag.add('accounts');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'TargetUserName', 'TargetDomainName', 'TargetSid', 'MemberName', 'MemberSid'
        );

      packSecuritySourceTarget(result, line);

      if(result.msvistalog.system.eventId === 4781) {
        // 4781: Account name changed
        // OldTargetUserName and NewTargetUserName; we'll tag the OldTargetUserName as the target,
        // and put the other in all
        parsedFields.push('OldTargetUserName', 'NewTargetUserName');

        result.log.all.samName = (line.TargetDomainName + '\\' + line.NewTargetUserName);
        result.log.target.samName = (line.TargetDomainName + '\\' + line.OldTargetUserName);
      }

      result.msvistalog.logon = {
        memberName: dashNull(line.MemberName),
        memberSid: line.MemberSid,
      };

      if(
        result.msvistalog.system.eventId === 4737 ||
        result.msvistalog.system.eventId === 4745 ||
        result.msvistalog.system.eventId === 4750 ||
        result.msvistalog.system.eventId === 4755 ||
        result.msvistalog.system.eventId === 4760) {
        // 4737: Global security group changed
        // 4745: Local non-security group changed
        // 4750: Global non-security group changed
        // 4755: Universal security group changed
        // 4760: Universal non-security group changed
        // There's no point in saying anything if the event doesn't tell us what changed
        if(line.PrivilegeList !== '-' || line.SamAccountName !== '-' || line.SidHistory !== '-')
          ctx.sendIrc('#infosec_accounts');
      }
      else {
        ctx.sendIrc('#infosec_accounts');
      }

      if(result.msvistalog.system.eventId === 4765 ||
        result.msvistalog.system.eventId === 4766 ||
        result.msvistalog.system.eventId === 4731 ||
        result.msvistalog.system.eventId === 4732 ||
        result.msvistalog.system.eventId === 4733 ||
        result.msvistalog.system.eventId === 4734 ||
        result.msvistalog.system.eventId === 4735 ||
        result.msvistalog.system.eventId === 4782) {
        // 4731: Local security group created
        // 4732: Local security group member added
        // 4733: Local security group member removed
        // 4734: Local security group deleted
        // 4735: Local security group changed
        // 4765: SID history added
        // 4766: SID history failed
        // 4782: Password hash accessed

        ctx.sendIrc('#infosec_critical');
        result.log.tag.add('critical');
      }
    }
    else if(result.msvistalog.system.eventId === 4780) {
      // ACL reset
      result.log.tag.add('parsed');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'TargetSid', 'TargetDomainName', 'TargetUserName');

      packSecuritySourceTarget(result, line);

      if(line.PrivilegeList !== '-')
        result.log.tag.add('bad-parse');

      // We ignore this event, even though it's only supposed to happen when the
      // admin security descriptors are wrong
      //ctx.sendIrc('#infosec_unknown_windows_security_events');
      result.log.tag.add('verbose');
    }
    else if(result.msvistalog.system.eventId === 4902) {
      // 4902: Per-user audit policy table was created, happens at startup

      result.log.tag.add('parsed');
      result.log.tag.add('verbose');
    }
    else if(result.msvistalog.system.eventId === 4904 || result.msvistalog.system.eventId === 4905) {
      // 4904/4905: Register/unregister security event source

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="AuditSourceName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="EventSourceId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'ProcessName');

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        processName: line.ProcessName,
      };

      if(result.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        ctx.sendIrc('#infosec_general_failures');
      }
      else if(result.msvistalog.logon.processName !== 'C:\\Windows\\System32\\VSSVC.exe') {
        ctx.sendIrc('#infosec_unknown_windows_security_events');
      }
    }
    else if(result.msvistalog.system.eventId === 4907) {
      // Auditing settings changed

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
          <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
          <data name="ObjectServer" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ObjectType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ObjectName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="HandleId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="OldSd" inType="win:UnicodeString" outType="xs:string"/>
          <data name="NewSd" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
          <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'ObjectServer', 'ObjectType', 'ObjectName', 'ProcessName'
        );

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        objectServer: line.ObjectServer,
        objectType: line.ObjectType,
        objectName: line.ObjectName,
        processName: dashNull(line.ProcessName),
      };
    }
    else if(result.msvistalog.system.eventId === 4776) {
      // Credential validation

      result.log.tag.add('parsed');
      result.log.tag.add('verbose');

      parsedFields.push(
        'PackageName', 'Workstation', 'Status'
        );

      result.msvistalog.logon = {
        authenticationPackageName: line.PackageName,
        workstationName: dashNull(line.Workstation),
        statusCode: toNumber(dashNull(line.Status)),
      };
    }
    else if(result.msvistalog.system.eventId === 4825) {
      // User denied access to remote desktop

      result.log.tag.add('parsed');

      parsedFields.push(
        'LogonID', 'ClientAddress', 'AccountDomain', 'AccountName'
        );

      result.log.source.logonId = line.LogonID;
      result.log.source.ip = parseIpv4(dashNull(line.ClientAddress));
      result.log.source.domain = line.AccountDomain;
      result.log.source.samName = line.AccountDomain + '\\' + line.AccountName;

      ctx.sendIrc('#infosec_critical');
    }
    else if(result.msvistalog.system.eventId === 5140) {
      // 5140: A network share object was accessed

      /*
        <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
        <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
        <data name="ObjectType" inType="win:UnicodeString" outType="xs:string"/>
        <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
        <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
        <data name="ShareName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="ShareLocalPath" inType="win:UnicodeString" outType="xs:string"/>
        <data name="AccessMask" inType="win:HexInt32" outType="win:HexInt32"/>
        <data name="AccessList" inType="win:UnicodeString" outType="xs:string"/>
      */

      result.log.tag.add('parsed');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId',
        'ObjectType', 'ShareName', 'AccessList'
        );

      packSecuritySourceTarget(result, line);

      result.msvistalog.logon = {
        processId: toNumber(dashNull(line.NewProcessId)),
        processName: dashNull(line.NewProcessName),
        objectType: line.ObjectType,
        shareName: line.ShareName,
        accessList: line.AccessList.trim().split(/\s+/g).map(v => {
          const type = accessTypeStrings.get(v);

          if(!type && !v.startsWith('{'))
            result.log.tag.add('bad-parse');

          return type || v;
        }),
      };
    }
    else if(
        result.msvistalog.system.eventId === 5442) {
      // 5442: The following provider was present when the Windows Filtering Platform Base Filtering Engine started.
      result.log.tag.add('parsed');
      result.log.tag.add('firewall');
      result.log.tag.add('verbose');

      if(line.ProviderName !== "Microsoft Corporation")
        ctx.sendIrc('#infosec_critical')
    }
    else if(
        result.msvistalog.system.eventId === 5446) {
      // 5449: Windows Filtering Platform provider context has been changed
      result.log.tag.add('parsed');
      result.log.tag.add('firewall');
      result.log.tag.add('verbose');

      result.log.source.sid = line.UserSid;
      result.log.source.samName = line.UserName;

      result.msvistalog.firewall = {
        layerRunTimeId: line.LayerRTID && +line.LayerRTID,
      };
    }
    else if(result.msvistalog.system.eventId === 5447) {
      // Windows Filtering Platform filter changed

      /*
        <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
          <data name="ProcessId" inType="win:UInt32" outType="xs:unsignedInt"/>
          <data name="UserSid" inType="win:SID" outType="xs:string"/>
          <data name="UserName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ProviderKey" inType="win:GUID" outType="xs:GUID"/>
          <data name="ProviderName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="ChangeType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="FilterKey" inType="win:GUID" outType="xs:GUID"/>
          <data name="FilterName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="FilterType" inType="win:UnicodeString" outType="xs:string"/>
          <data name="FilterId" inType="win:UInt64" outType="xs:unsignedLong"/>
          <data name="LayerKey" inType="win:GUID" outType="xs:GUID"/>
          <data name="LayerName" inType="win:UnicodeString" outType="xs:string"/>
          <data name="LayerId" inType="win:UInt32" outType="xs:unsignedInt"/>
          <data name="Weight" inType="win:UInt64" outType="xs:unsignedLong"/>
          <data name="Conditions" inType="win:UnicodeString" outType="xs:string"/>
          <data name="Action" inType="win:UnicodeString" outType="xs:string"/>
          <data name="CalloutKey" inType="win:GUID" outType="xs:GUID"/>
          <data name="CalloutName" inType="win:UnicodeString" outType="xs:string"/>
        </template>
      */

      result.log.tag.add('parsed');
      result.log.tag.add('firewall');

      parsedFields.push(
        'UserSid', 'UserName'
        );

      result.log.source.sid = line.UserSid;
      result.log.source.samName = line.UserName;
    }
    else if(
        result.msvistalog.system.eventId === 5449) {
      // 5449: Windows Filtering Platform provider context has been changed
      result.log.tag.add('parsed');
      result.log.tag.add('firewall');
      result.log.tag.add('verbose');

      parsedFields.push(
        'UserSid', 'UserName'
        );

      result.log.source.sid = line.UserSid;
      result.log.source.samName = line.UserName;
    }
    else if(result.msvistalog.system.eventId === 6281) {
      // System integrity error on a file path
      // Count this one as parsed even though we don't do anything with the file name field

      result.log.tag.add('parsed');
    }
    else if(result.msvistalog.system.eventId >= 6272 && result.msvistalog.system.eventId <= 6280) {
      // 6272: Network Policy Server granted access to a user.
      // 6273: Network Policy Server denied access to a user.
      // 6274: Network Policy Server discarded the request for a user.
      // 6275: Network Policy Server discarded the accounting request for a user.
      // 6276: Network Policy Server quarantined a user.
      // 6277: Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy.
      // 6278: Network Policy Server granted full access to a user because the host met the defined health policy.
      // 6279: Network Policy Server locked the user account due to repeated failed authentication attempts.
      // 6280: Network Policy Server unlocked the user account.

      /*
        <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
        <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="FullyQualifiedSubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="SubjectMachineSID" inType="win:SID" outType="xs:string"/>
        <data name="SubjectMachineName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="FullyQualifiedSubjectMachineName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="MachineInventory" inType="win:UnicodeString" outType="xs:string"/>
        <data name="CalledStationID" inType="win:UnicodeString" outType="xs:string"/>
        <data name="CallingStationID" inType="win:UnicodeString" outType="xs:string"/>
        <data name="NASIPv4Address" inType="win:UnicodeString" outType="xs:string"/>
        <data name="NASIPv6Address" inType="win:UnicodeString" outType="xs:string"/>
        <data name="NASIdentifier" inType="win:UnicodeString" outType="xs:string"/>
        <data name="NASPortType" inType="win:UnicodeString" outType="xs:string"/>
        <data name="NASPort" inType="win:UnicodeString" outType="xs:string"/>
        <data name="ClientName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="ClientIPAddress" inType="win:UnicodeString" outType="xs:string"/>
        <data name="ProxyPolicyName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="NetworkPolicyName" inType="win:UnicodeString" outType="xs:string"/>
        <data name="AuthenticationProvider" inType="win:UnicodeString" outType="xs:string"/>
        <data name="AuthenticationServer" inType="win:UnicodeString" outType="xs:string"/>
        <data name="AuthenticationType" inType="win:UnicodeString" outType="xs:string"/>
        <data name="EAPType" inType="win:UnicodeString" outType="xs:string"/>
        <data name="AccountSessionIdentifier" inType="win:UnicodeString" outType="xs:string"/>
        <data name="QuarantineState" inType="win:UnicodeString" outType="xs:string"/>
        <data name="QuarantineSessionIdentifier" inType="win:UnicodeString" outType="xs:string"/>
      */

      parsedFields.push(
        'SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectMachineSID',
        'CalledStationID', 'CallingStationID', 'NASIPv4Address', 'NASIdentifier',
        'NASPortType', 'ClientName', 'ClientIPAddress', 'ProxyPolicyName', 'NetworkPolicyName',
        'AuthenticationProvider', 'AuthenticationServer', 'AuthenticationType', 'ReasonCode', 'Reason'
        );

      result.log.source.ip = line.ClientIPAddress;
      result.log.source.mac = (line.CallingStationID && line.CallingStationID !== '-') ? line.CallingStationID.replace('-', '').toLowerCase() : undefined;

      result.networkPolicy = {
        proxyPolicyName: dashNull(line.ProxyPolicyName),
        networkPolicyName: dashNull(line.NetworkPolicyName),
        reasonCode: (line.ReasonCode !== undefined && line.ReasonCode !== '-') ? +line.ReasonCode : undefined,
        loggingResult: dashNull(line.loggingResult),
        reason: dashNull(line.Reason),
        authenticationType: dashNull(line.AuthenticationType),
        nasIpv4Address: dashNull(line.NASIPv4Address),
        calledStationId: dashNull(line.CalledStationID),
        callingStationId: dashNull(line.CallingStationID),
        nasIdentifier: dashNull(line.NASIdentifier),
        nasPortType: dashNull(line.NASPortType),
        clientName: dashNull(line.ClientName),
        clientIpAddress: dashNull(line.ClientIPAddress),
        authenticationProvider: dashNull(line.AuthenticationProvider),
        authenticationServer: dashNull(line.AuthenticationServer),
      };

      result.log.tag.add('parsed');
      result.log.tag.add('network-policy');
    }
    else if(result.msvistalog.system.eventId === 5024 ||
      result.msvistalog.system.eventId === 5033) {

      // Windows Firewall success events

      // 5024: Windows Firewall service started successfully
      // 5033: Windows Firewall Driver started successfully

      result.log.tag.add('parsed');
      result.log.tag.add('firewall');
    }
    else if(result.msvistalog.system.eventId === 5889 || result.msvistalog.system.eventId === 5890) {
      // 5889: Object deleted from COM+ catalog
      // 5890: Object added to COM+ catalog

      // Not terribly interesting

      result.log.tag.add('parsed');
      result.log.tag.add('verbose');

      parsedFields.push(
        'SubjectUserSid', 'SubjectDomainName', 'SubjectUserName', 'SubjectLogonId'
        );

      packSecuritySourceTarget(result, line);
    }
    else {
      ctx.sendIrc('#infosec_unknown_windows_security_events');
    }
  }
  else if(result.msvistalog.system.provider.guid === '555908D1-A6D7-4695-8E1E-26931D2012F4') {
    result.log.tag.add('services');

    // Service control manager
    if(result.msvistalog.system.eventId === 7036) {
      // Service changed state
      result.log.tag.add('parsed');

      parsedFields.push('param1', 'param2');

      result.msvistalog.service = {
        serviceName: line.param1,
        state: line.param2,
      };

      // Temp: send word about PSEXESVC to windows logons so we don't lose it
      if(line.param1.toUpperCase() === 'PSEXESVC') {
        ctx.sendIrc('#infosec_critical');
      }
    }
    else if(result.msvistalog.system.eventId === 7045) {
      // 7045: A service was installed in the system
      result.log.tag.add('parsed');

      parsedFields.push('ServiceName');

      result.msvistalog.service = {
        serviceName: line.ServiceName,
      };

      ctx.sendIrc('#infosec_critical');
    }
  }
  else if(result.msvistalog.system.provider.guid === '331C3B3A-2005-44C2-AC5E-77220C37D6B4') {
    result.log.tag.add('power');

    if(result.msvistalog.system.eventId === 41) {
      // Unclean reboot
      ctx.sendIrc('#infosec_critical');
    }
  }
  else if(result.msvistalog.system.provider.eventSourceName === 'MsiInstaller') {
    result.log.tag.add('installer');

    if(result.msvistalog.system.eventId !== 1035 &&
      result.msvistalog.system.eventId !== 1025 &&
      result.msvistalog.system.eventId !== 1040 &&
      result.msvistalog.system.eventId !== 1042) {
      // Ignore 1025: File in use
      // Ignore 1035: Reconfiguration, which seems to happen whenever the installer runs
      // Ignore 1040 and 1042: Transaction start/end

      ctx.sendIrc('#infosec_installer');
    }
  }

  parsedFields = new Set(parsedFields);

  for(let key of Object.keys(line)) {
    if(!systemFields.has(key)) {
      result.msvistalog.other[key] = line[key];
      result.msvistalog.otherFields.push(key);

      if(!parsedFields.has(key))
        result.msvistalog.unparsedFields.push(key);
    }
  }

  if(!result.msvistalog.otherFields.length) {
    // Nothing to parse, really
    result.log.tag.add('parsed');
  }

  if(result.log.tag.has('bad-parse'))
    ctx.sendIrc('#bad_parse');

  result.log.tag = Array.from(result.log.tag);

  // Ensure fields are properly cased
  for(let area of ['all', 'source', 'target']) {
    for(let field of ['samName', 'domain', 'sid', 'hostname'])
      result.log[area][field] = uppercase(result.log[area][field]);

    for(let field of ['fqdn', 'upn'])
      result.log[area][field] = lowercase(result.log[area][field]);
  }

  const buffer = Buffer.allocUnsafe(8);
  buffer.writeUIntLE(new Date(result.log.receivedTime).getTime(), 0, 8);

  ctx.meta.finderUrl = 'https://localhost/investigator/?vl=' + encodeURIComponent(shortenBase64(buffer.toString('base64')) + '-' + result.log.recordFinder);
  ctx.sendFile(`${ctx.meta.remoteAddress}/${fileDateFormat(new Date(ctx.meta.receiveTime))}/msvistalog-${localHourFormat(new Date(ctx.meta.receiveTime))}.jsonlog`);
  ctx.sendElasticsearch('msvistalog-' + dateFormat(result.log.receivedTime), 'msvistalog');

  return result;
}


/****** IRC ******/

function ellipsify(str, length) {
  if(str.length > length)
    return str.substring(0, length - 3) + '...';

  return str;
}

function ircEscape(str) {
  if(!str)
    return '(blank)';

  return str.replace(/[\x00-\x1f]/g, ' ');
}

const logonTypeText = new Map([
  [2, '\x0304,99an interactive logon\x0f'],
  [3, 'a network logon'],
  [4, 'a batch logon'],
  [5, 'a service logon'],
  [7, 'an unlock'],
  [8, '\x02\x0304,99a network clear text logon\x0f'],
  [9, 'a "new credentials" logon'],
  [10, '\x02\x0304,99a remote interactive logon\x0f'],
  [11, 'a cached interactive logon'],
]);

const logonTypeFailureSlackTitles = new Map([
  [2, 'Interactive logon failure'],
  [3, 'Network logon failure'],
  [4, 'Batch logon failure'],
  [5, 'Service logon failure'],
  [7, 'Unlock failure'],
  [8, 'Network cleartext logon failure'],
  [9, '"New credentials" logon failure'],
  [10, 'Remote interactive logon failure'],
  [11, 'Cached interactive logon failure'],
]);

function makeIrcMessage(ctx, msg) {
  if(msg.msvistalog.system.provider.guid === '54849625-5478-4994-A5BA-3E3B0328C30D') {
    const processName = ((msg.msvistalog.logon && msg.msvistalog.logon.processName) || '(unknown)').replace(/^.+\\+/, '');
    const sourceIp = (msg.log.source.ip && ` from \x02${msg.log.source.ip}\x0f` || '');

    let memberName = undefined;

    if(msg.msvistalog.logon) {
      const articles = ctx.wikiMap.bySid.get(msg.msvistalog.logon.memberSid);

      if(articles && articles.length) {
        memberName = articles[0].title;
      }

      if(!memberName && msg.msvistalog.logon.memberName) {
        const dn = parseDN(msg.msvistalog.logon.memberName);
        memberName = dn[0].value;
      }

      if(!memberName)
        memberName = '(unknown name)';
    }

    // Special processing for security messages
    if(msg.msvistalog.system.eventId === 4624) {
      if(msg.msvistalog.logon.lmPackageName && msg.msvistalog.logon.lmPackageName !== 'NTLM V2') {
        return `${ircEscape(msg.log.target.samName)} performed ${logonTypeText.get(msg.msvistalog.logon.logonType) || 'an unknown logon type'}${sourceIp} via \x02\x0304,99a non-NTLM protocol\x0f (${ircEscape(msg.msvistalog.logon.lmPackageName)}).`;
      }
      else {
        return `${ircEscape(msg.log.target.samName)} performed ${logonTypeText.get(msg.msvistalog.logon.logonType) || 'an unknown logon type'}${sourceIp} via ${ircEscape(processName)} using ${ircEscape(msg.msvistalog.logon.authenticationPackageName)}.`;
      }
    }
    else if(msg.msvistalog.system.eventId === 4625) {
      if(msg.msvistalog.other.Status === '0xc0000198') {
        return `\x02${ircEscape(msg.log.target.samName || msg.log.target.upn)}\x0f logon failed because it\'s an interdomain trust account.`;
      }
      else if(msg.msvistalog.other.Status === '0xc0000199') {
        return `\x02${ircEscape(msg.log.target.samName || msg.log.target.upn)}\x0f logon failed because it\'s a workstation trust account.`;
      }
      else if(msg.msvistalog.other.Status === '0xc000019a') {
        return `\x02${ircEscape(msg.log.target.samName || msg.log.target.upn)}\x0f logon failed because it\'s a domain controller trust account.`;
      }
      else if(msg.msvistalog.logon.lmPackageName && msg.msvistalog.logon.lmPackageName !== 'NTLM V2') {
        return `\x02${ircEscape(msg.log.target.samName || msg.log.target.upn)}\x0f failed to perform ${logonTypeText.get(msg.msvistalog.logon.logonType) || 'an unknown logon type'}${sourceIp} via \x02\x0304,99a non-NTLM protocol\x0f (${ircEscape(msg.msvistalog.logon.lmPackageName)}).`;
      }
      else {
        return `\x02${ircEscape(msg.log.target.samName || msg.log.target.upn)}\x0f failed to perform ${logonTypeText.get(msg.msvistalog.logon.logonType) || 'an unknown logon type'}${sourceIp}${msg.log.source.hostname && (' (' + msg.log.source.hostname + ')') || ''} via ${ircEscape(processName)} using ${ircEscape(msg.msvistalog.logon.authenticationPackageName)}: \x0304,99${ircEscape(msg.msvistalog.logon.failureReason)}\x0f`;
      }
    }
    else if(msg.msvistalog.system.eventId === 4647) {
      return `${ircEscape(msg.log.target.samName)} logged off.`;
    }
    else if(msg.msvistalog.system.eventId === 4720) {
      // 4720: Create acccount
      return `${ircEscape(msg.log.source.samName)} ${(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') ? '\x0304,99tried to create an account' : '\x0303,99created an account'}\x0f ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4722) {
      // 4722: Enable account
      return `${ircEscape(msg.log.source.samName)} ${(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') ? '\x0304,99tried to enable the account\x0f' : 'enabled the account'} ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4724) {
      // 4724: Reset password
      return `${ircEscape(msg.log.source.samName)} \x0304,99${(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') ? 'tried to ' : ''}reset the password\x0f for ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4725) {
      // 4725: Disable account
      return `${ircEscape(msg.log.source.samName)} ${(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') ? '\x0304,99tried to disable the account\x0f' : 'disabled the account'} ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4726) {
      // 4726: Delete account
      return `${ircEscape(msg.log.source.samName)} \x0304,99${(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') ? 'tried to delete the account' : 'deleted the account'}\x0f ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4738 || msg.msvistalog.system.eventId === 4742) {
      // 4738: Account changed
      // 4742: Computer account changed
      const setAttrs = accountChangeAttrs.filter(attr => msg.msvistalog.other[attr] !== '-' && msg.msvistalog.other[attr] !== undefined);

      const attrSet = new Set(setAttrs);

      // Some special cases
      if(attrSet.size === 1 && attrSet.has('PasswordLastSet')) {
        if(msg.log.source.samName === 'NT AUTHORITY\\ANONYMOUS LOGON') {
          return `${msg.log.target.samName} changed ${msg.msvistalog.system.eventId === 4738 ? 'their' : 'its'} own password.`;
        }
        else {
          return `${msg.log.source.samName} \x0304,99changed the password\x0f for ${msg.log.target.samName}.`;
        }
      }

      if(attrSet.size === 0) {
        return `${msg.log.source.samName} changed unspecified properties on ${msg.log.target.samName}.`;
      }

      return `${ircEscape(msg.log.source.samName)} changed the following properties on ${ircEscape(msg.log.target.samName)}: ${setAttrs.join(', ')}`;
    }
    else if(msg.msvistalog.system.eventId === 4740) {
      // 4740: Account locked out
      return `${ircEscape(msg.log.target.samName)} was \x0304,99locked out\x0f from ${ircEscape(msg.log.target.hostname)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4741) {
      // 4741: Create computer acccount
      return `${ircEscape(msg.log.source.samName)} ${(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') ? '\x0304,99tried to create a computer' : '\x0303,99created a computer'}\x0f ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4743) {
      // 4743: Delete computer acccount
      return `${ircEscape(msg.log.source.samName)} ${(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') ? '\x0304,99tried to delete computer' : '\x0304,99deleted computer'}\x0f ${ircEscape(msg.log.target.samName)}.`;
    }

    // Security/distribution groups
    else if(msg.msvistalog.system.eventId === 4727) {
      // 4727: Global security group created
      return `${ircEscape(msg.log.source.samName)} \x0303,99created\x0f the global security group ${ircEscape(msg.msvistalog.other.TargetDomainName)}\\${ircEscape(msg.msvistalog.other.TargetUserName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4728) {
      // 4728: Global security group member added
      return `${ircEscape(msg.log.source.samName)} \x0303,99added\x0f ${ircEscape(memberName)} to the global security group ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4729) {
      // 4729: Global security group member removed
      return `${ircEscape(msg.log.source.samName)} \x0304,99removed\x0f ${ircEscape(memberName)} from the global group ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4730) {
      // 4730: Global security group deleted
      return `${ircEscape(msg.log.source.samName)} \x0303,99deleted\x0f the global security group ${ircEscape(msg.msvistalog.other.TargetDomainName)}\\${ircEscape(msg.msvistalog.other.TargetUserName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4731) {
      // 4731: Local security group created
      return `${ircEscape(msg.log.source.samName)} \x0303,99created\x0f the local security group ${ircEscape(msg.msvistalog.other.TargetDomainName)}\\${ircEscape(msg.msvistalog.other.TargetUserName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4732) {
      // 4732: Local security group member added
      return `${ircEscape(msg.log.source.samName)} \x0303,99added\x0f ${ircEscape(memberName)} to the local security group ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4732) {
      // 4732: Local security group member removed
      return `${ircEscape(msg.log.source.samName)} \x0304,99removed\x0f ${ircEscape(memberName)} from the local group ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4734) {
      // 4734: Local security group deleted
      return `${ircEscape(msg.log.source.samName)} \x0303,99deleted\x0f the local security group ${ircEscape(msg.msvistalog.other.TargetDomainName)}\\${ircEscape(msg.msvistalog.other.TargetUserName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4756) {
      // 4756: Universal security group member added
      return `${ircEscape(msg.log.source.samName)} \x0303,99added\x0f ${ircEscape(memberName)} to the security group ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4757) {
      // 4757: Universal security group member removed
      return `${ircEscape(msg.log.source.samName)} \x0304,99removed\x0f ${ircEscape(memberName)} from the security group ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4759) {
      // 4759: Universal non-security group created
      return `${ircEscape(msg.log.source.samName)} \x0303,99created\x0f the distribution group ${ircEscape(msg.msvistalog.other.TargetDomainName)}\\${ircEscape(msg.msvistalog.other.TargetUserName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4761) {
      // 4760: Universal non-security group changed

      // 4761: User added to distribution group
      return `${ircEscape(msg.log.source.samName)} \x0303,99added\x0f ${ircEscape(memberName)} to the distribution group ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4762) {
      // 4762: Universal non-security group member removed
      return `${ircEscape(msg.log.source.samName)} \x0304,99removed\x0f ${ircEscape(memberName)} from the distribution group ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4763) {
      // 4763: Universal non-security group deleted
      return `${ircEscape(msg.log.source.samName)} \x0303,99deleted\x0f the distribution group ${ircEscape(msg.msvistalog.other.TargetDomainName)}\\${ircEscape(msg.msvistalog.other.TargetUserName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4767) {
      // 4767: User account unlocked
      return `${ircEscape(msg.log.source.samName)} \x0303,99unlocked\x0f ${ircEscape(msg.log.target.samName)}.`;
    }
    else if(msg.msvistalog.system.eventId === 4768) {
      if(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        if(msg.msvistalog.logon.statusCode === 0x6) {
          return `[TGT] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f tried to log in as \x0304,99invalid user\x0f \x02${ircEscape(msg.log.target.upn || msg.log.target.samName)}\x0f.`;
        }
        else if(msg.msvistalog.logon.statusCode === 0x12) {
          return `[TGT] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f tried to log in as \x0304,99disabled user\x0f \x02${ircEscape(msg.log.target.upn || msg.log.target.samName)}\x0f.`;
        }
        else if(msg.msvistalog.logon.statusCode === 0x17) {
          return `[TGT] \x02${ircEscape(msg.log.target.upn || msg.log.target.samName)}\x0f tried to log in from \x02${ircEscape(msg.log.source.ip)}\x0f with an \x0304,99expired password\x0f.`;
        }
        else if(msg.msvistalog.logon.statusCode === 0x18) {
          return `[TGT] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f tried to log in as \x02${ircEscape(msg.log.target.upn || msg.log.target.samName)}\x0f with an \x0304,99incorrect password\x0f.`;
        }
        else {
          return `[TGT] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f failed to get a TGT for \x02${ircEscape(msg.log.target.upn || msg.log.target.samName)}\x0f (status code ${msg.msvistalog.logon.statusCode}).`;
        }
      }
      else {
        return `[TGT] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f retrieved a TGT for \x02${ircEscape(msg.log.target.upn || msg.log.target.samName)}\x0f.`
      }
    }
    else if(msg.msvistalog.system.eventId === 4769) {
      if(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        if(msg.msvistalog.logon.statusCode === 0x20) {
          return `[Service] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f failed to get a service ticket due to an expired ticket.`;
        }
        else if(msg.msvistalog.logon.statusCode === 0x1b) {
          return `[Service] \x02${msg.log.source.upn}\x0f from \x02${ircEscape(msg.log.source.ip)}\x0f failed to get a service ticket for \x02${ircEscape(msg.log.target.serviceName)}\x0f (possible missing SPN).`;
        }
        else if(msg.msvistalog.logon.statusCode === 37) {
          return `[Service] \x02${msg.log.source.upn}\x0f from \x02${ircEscape(msg.log.source.ip)}\x0f failed to get a service ticket for \x02${ircEscape(msg.log.target.serviceName)}\x0f (large clock skew).`;
        }
        else {
          return `[Service] \x02${msg.log.source.upn}\x0f from \x02${ircEscape(msg.log.source.ip)}\x0f failed to get a service ticket for \x02${ircEscape(msg.log.target.serviceName)}\x0f (status code ${msg.msvistalog.logon.statusCode}).`;
        }
      }
      else {
        return `[Service] \x02${msg.log.source.upn}\x0f from ${ircEscape(msg.log.source.ip)} retrieved a service ticket for \x02${ircEscape(msg.log.target.serviceName)}\x0f.`
      }
    }
    else if(msg.msvistalog.system.eventId === 4771) {
      if(msg.msvistalog.logon.statusCode === 0x6) {
        return `[Preauth] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f tried to log in as \x0304,99invalid user\x0f \x02${ircEscape(msg.msvistalog.other.TargetUserName)}\x0f.`;
      }
      else if(msg.msvistalog.logon.statusCode === 0x12) {
        return `[Preauth] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f tried to log in as \x0304,99disabled user\x0f \x02${ircEscape(msg.msvistalog.other.TargetUserName)}\x0f.`;
      }
      else if(msg.msvistalog.logon.statusCode === 0x17) {
        return `[Preauth] \x02${ircEscape(msg.msvistalog.other.TargetUserName)}\x0f tried to log in from \x02${ircEscape(msg.log.source.ip)}\x0f with an \x0304,99expired password\x0f.`;
      }
      else if(msg.msvistalog.logon.statusCode === 0x18) {
        return `[Preauth] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f tried to log in as \x02${ircEscape(msg.msvistalog.other.TargetUserName)}\x0f with an \x0304,99incorrect password\x0f.`;
      }
      else if(msg.msvistalog.logon.statusCode === 37) {
        return `[Preauth] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f failed to log in as \x02${ircEscape(msg.msvistalog.other.TargetUserName)}\x0f due to a \x0304,99large clock skew\x0f.`;
      }
      else {
        return `[Preauth] Someone from \x02${ircEscape(msg.log.source.ip)}\x0f failed to log in as \x02${ircEscape(msg.msvistalog.other.TargetUserName)}\x0f (status code ${msg.msvistalog.logon.statusCode}).`;
      }
    }
    else if(msg.msvistalog.system.eventId === 4780) {
      // ACL reset
      return `Domain controller reset the ACL for admin account \x02${ircEscape(msg.log.target.samName)}\x0f because it differs from AdminSDHolder.`;
    }
    else if(msg.msvistalog.system.eventId === 4781) {
      // Account name change
      return `${ircEscape(msg.log.source.samName)} \x0304,99renamed\x0f \x0312,99${ircEscape(msg.msvistalog.other.OldTargetUserName)}\x0f to \x0312,99${ircEscape(msg.msvistalog.other.NewTargetUserName)}\x0f.`;
    }
  }
  else if(msg.msvistalog.system.provider.guid === '555908D1-A6D7-4695-8E1E-26931D2012F4') {
    if(msg.msvistalog.system.eventId === 7045) {
      return `${ircEscape(msg.msvistalog.system.samName)} \x0307,99installed\x0f ${ircEscape(msg.msvistalog.service.serviceName)}.`;
    }
  }

  if(msg.log.message) {
    return ircEscape(msg.log.message);
  }

  return '(no message)';
}

function formatIrc(ctx, msg, skipCutoff) {
  // Don't report anything more than a day ago
  const cutoffDate = d3.timeDay.offset(new Date(), -1);

  if(!skipCutoff && msg.log.eventTime < cutoffDate)
    return null;

  var str = '';

  if(msg.msvistalog.system.eventType === 'ERROR') {
    // White text on red background
    str += '\x0300,04 ERROR \x03 ';
  }
  else if(msg.msvistalog.system.eventType === 'WARNING') {
    // White text on orange background
    str += '\x0300,07 WARNING \x03 ';
  }
  else if(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') {
    // White text on orange background
    str += '\x0300,07 AUDIT FAILURE \x03 ';
  }
  else if(msg.msvistalog.system.eventType === 'AUDIT_SUCCESS') {
    // White text on green background
    str += '\x0300,03 AUDIT SUCCESS \x03 ';
  }
  else if(msg.msvistalog.system.eventType === 'INFO') {
    // White text on green background
    str += '\x0300,03 INFO \x03 ';
  }

  if(msg.msvistalog.other && msg.msvistalog.other.SidHistory && msg.msvistalog.other.SidHistory !== '-') {
    str += '\x0304,99[SID HISTORY]\x0f ';
  }

  str += ellipsify(makeIrcMessage(ctx, msg), 200) + '\x0f';

  const addlInfo = [];

  //if(msg.wsa.request.username)
  //  addlInfo.push('as ' + ircEscape(msg.wsa.request.samName || msg.wsa.request.username));

  addlInfo.push(msg.msvistalog.system.eventId + '');

  if(msg.msvistalog.system.taskName)
    addlInfo.push('"' + ircEscape(msg.msvistalog.system.taskName) + '"');

  if(msg.msvistalog.system.computer)
    addlInfo.push('from ' + ircEscape(msg.msvistalog.system.computer));

  if(addlInfo.length)
    str += ' \x0314(' + addlInfo.join(' ') + ')';

  str += '\x0315 ' + ctx.meta.finderUrl;

  return str;
}

const ESCAPE_CHARS = {
  '<': '&lt;', '>': '&gt;', '&': '&amp;'
};

function slackEscape(str) {
  if(!str)
    return '(blank)';

  return str.replace(/[<>&]/g, match => ESCAPE_CHARS[match]);
}

function formatSlack(ctx, msg) {
  const compArticle = getArticle(ctx, {fqdn: msg.msvistalog.system.computer});

  const sourceIsDC = compArticle && compArticle.tags.has('domain-controller');
  const domain = guessDomainFromFqdn(msg.msvistalog.system.computer);
  const hostname = hostnameFromFqdn(msg.msvistalog.system.computer).toUpperCase();

  const result = {
    attachments: [
      {
        fallback: null,
        color: "#ffd700",
        text: null,
        footer: `Reported by ${slackLinkToArticle(compArticle, msg.msvistalog.system.computer)} | <${ctx.meta.finderUrl}|${msg.msvistalog.system.eventId}${msg.msvistalog.system.taskName ? (' ' + msg.msvistalog.system.taskName) : ''}>`,
        ts: msg.log.eventTime.getTime() * 0.001,
      }
    ]
  };

  const mainAttach = result.attachments[0];

  if(msg.msvistalog.system.provider.guid === '54849625-5478-4994-A5BA-3E3B0328C30D') {
    if(msg.msvistalog.system.eventId === 4625) {
      //   0xc00002ee/0x0 STATUS_UNFINISHED_CONTEXT_DELETED
      //   0xc000005e/0x0 STATUS_NO_LOGON_SERVERS
      //   0xc000006d/(several) STATUS_LOGON_FAILURE
      //      0xc0000064 STATUS_NO_SUCH_USER
      //      0xc000006a STATUS_WRONG_PASSWORD
      //   0xc000006e/(several) STATUS_ACCOUNT_RESTRICTION
      //      0xc0000071 STATUS_PASSWORD_EXPIRED
      //      0xc0000072 STATUS_ACCOUNT_DISABLED
      //      0xc000006f STATUS_INVALID_LOGON_HOURS
      //   0xc0000224/0x0 STATUS_PASSWORD_MUST_CHANGE
      //   0xc000015b/0x0 STATUS_LOGON_TYPE_NOT_GRANTED
      //   0xc0000234/0x0 STATUS_ACCOUNT_LOCKED_OUT
      //   0xc0000017/0x0 STATUS_NO_MEMORY
      //   0xc0000192/0x0 STATUS_NETLOGON_NOT_STARTED
      //   0xc0000133/0x0 STATUS_TIME_DIFFERENCE_AT_DC
      //   0xc000018d/0x0 STATUS_TRUSTED_RELATIONSHIP_FAILURE
      //   0xc00000dc/0x0 STATUS_INVALID_SERVER_STATE

      const processName = ((msg.msvistalog.logon && msg.msvistalog.logon.processName) || '(unknown)').replace(/^.+\\+/, '');

      mainAttach.color = 'warning';
      mainAttach.title = logonTypeFailureSlackTitles.get(msg.msvistalog.logon.logonType) || 'Unknown logon failure';
      mainAttach.mrkdwn_in = ['text'];

      let workstationText = null;

      if(msg.msvistalog.logon.workstationName) {
        if(msg.log.source.ip) {
          workstationText = `${msg.msvistalog.logon.workstationName} (${msg.log.source.ip})`;
        }
        else {
          workstationText = `${msg.msvistalog.logon.workstationName}`;
        }
      }
      else {
        if(msg.log.source.ip) {
          workstationText = `${msg.log.source.ip}`;
        }
      }

      if(msg.msvistalog.other.Status === '0xc000015b') {
        mainAttach.text = `${slackLinkToArticle(ctx.meta.targetArticle, msg.log.target.samName || msg.log.target.upn)} failed to log in to ${slackLinkToArticle(compArticle, msg.msvistalog.system.computer)} because they have not been granted this logon type.`;
        mainAttach.fallback = `${slackEscape(msg.log.target.samName || msg.log.target.upn)} failed to log in to ${slackEscape(msg.msvistalog.system.computer)} because they have not been granted this logon type.`;
      }
      else if(msg.msvistalog.other.SubStatus === '0xc000006a') {
        mainAttach.text = `Someone tried to log in to ${slackLinkToArticle(compArticle, msg.msvistalog.system.computer)} as ${slackLinkToArticle(ctx.meta.targetArticle, msg.log.target.samName || msg.log.target.upn)} with an *incorrect password*.`;
        mainAttach.fallback = `Someone${workstationText ? (' from ' + slackEscape(workstationText)) : ''} tried to log in to ${slackEscape(msg.msvistalog.system.computer)} as ${slackEscape(msg.log.target.samName || msg.log.target.upn)} with an incorrect password.`;
      }
      else if(msg.msvistalog.other.SubStatus === '0xc0000064') {
        mainAttach.text = `Someone tried to log in to ${slackLinkToArticle(compArticle, msg.msvistalog.system.computer)} as *invalid user* ${slackLinkToArticle(ctx.meta.targetArticle, msg.log.target.samName || msg.log.target.upn)}.`;
        mainAttach.fallback = `Someone${workstationText ? (' from ' + slackEscape(workstationText)) : ''} tried to log in to ${slackEscape(msg.msvistalog.system.computer)} as invalid user ${slackEscape(msg.log.target.samName || msg.log.target.upn)}.`;
      }
      else {
        mainAttach.text = `${slackLinkToArticle(ctx.meta.targetArticle, msg.log.target.samName || msg.log.target.upn)} failed to log in to ${slackLinkToArticle(compArticle, msg.msvistalog.system.computer)}: ${slackEscape(msg.msvistalog.logon.failureReason)}`;
        mainAttach.fallback = `${slackEscape(msg.log.target.samName || msg.log.target.upn)} failed to log in to ${slackEscape(msg.msvistalog.system.computer)}${workstationText ? (' from ' + slackEscape(workstationText)) : ''}: ${ircEscape(msg.msvistalog.logon.failureReason)}`;
      }

      if(workstationText) {
        mainAttach.text += `\n• Workstation: ${workstationText}`;
      }

      const reasons = [];

      if(ctx.meta.neverLogon) {
        reasons.push('• *The user was marked `never-logon`.*');
      }

      if(ctx.meta.builtinAdmin) {
        reasons.push('• The user is a built-in adminstrator.');
      }

      if(ctx.meta.enterpriseAdmin) {
        reasons.push('• The user is an enterprise admin.');
      }
      else if(ctx.meta.domainAdmin) {
        reasons.push('• The user is a domain admin.');
      }

      if(reasons.length) {
        result.attachments.push({
          text: 'This alert was raised because:\n' + reasons.join('\n'),
          mrkdwn_in: ['text'],
          color: 'danger'
        });
      }

      return result;
    }
    else if(msg.msvistalog.system.eventId === 4768) {
      // 4768: Kerberos TGT attempt
      mainAttach.mrkdwn_in = ['text'];

      if(msg.msvistalog.system.eventType === 'AUDIT_FAILURE') {
        mainAttach.title = 'Kerberos TGT failure';
        mainAttach.color = 'danger';

        if(msg.msvistalog.logon.statusCode === 0x12) {
          mainAttach.fallback = `[Kerberos TGT] Someone from ${slackEscape(msg.log.source.ip)} tried to log in as disabled user ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)}.`;
          mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* tried to log in as *disabled user* *${slackLinkToArticle(ctx.meta.sourceArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}*.`;
        }
        else if(msg.msvistalog.logon.statusCode === 0x6) {
          mainAttach.fallback = `[Kerberos TGT] Someone from ${slackEscape(msg.log.source.ip)} tried to log in as invalid user ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)}.`;
          mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* tried to log in as *invalid user* *${slackLinkToArticle(ctx.meta.sourceArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}*.`;
        }
        else if(msg.msvistalog.logon.statusCode === 0x17) {
          mainAttach.fallback = `[Kerberos TGT] ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)} tried to log in from ${slackEscape(msg.log.source.ip)} with an expired password.`;
          mainAttach.text = `*${slackLinkToArticle(ctx.meta.sourceArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}* tried to log in from *${slackEscape(msg.log.source.ip)}* with an *expired password*.`;
          mainAttach.color = 'warning';
        }
        else if(msg.msvistalog.logon.statusCode === 0x18) {
          mainAttach.fallback = `[Kerberos TGT] Someone from ${slackEscape(msg.log.source.ip)} tried to log in as ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)} with an incorrect password.`;
          mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* tried to log in as *${slackLinkToArticle(ctx.meta.sourceArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}* with an *incorrect password*.`;
          mainAttach.color = 'warning';
        }
        else if(msg.msvistalog.logon.statusCode === 0x25) {
          mainAttach.fallback = `[Kerberos TGT] Someone from ${slackEscape(msg.log.source.ip)} failed to log in as ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)} due to a large clock skew.`;
          mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* failed to log in as *${slackLinkToArticle(ctx.meta.sourceArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}* due to a large clock skew.`;
          mainAttach.color = 'warning';
        }
        else {
          mainAttach.fallback = `[Kerberos TGT] Someone from ${slackEscape(msg.log.source.ip)} failed to log in as ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)} (status code ${msg.msvistalog.logon.statusCode}).`;
          mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* failed to log in as *${slackLinkToArticle(ctx.meta.sourceArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}* (status code ${msg.msvistalog.logon.statusCode}).`;
          mainAttach.color = 'warning';
        }
      }
      else {
        mainAttach.title = 'Kerberos login';
        mainAttach.color = 'warning';
        mainAttach.fallback = `[Kerberos] Someone from ${slackEscape(msg.log.source.ip)} logged in as ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)}.`;
        mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* logged in as *${slackLinkToArticle(ctx.meta.sourceArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}*.`;
        mainAttach.color = 'warning';
      }

      const reasons = [];

      if(ctx.meta.neverLogon) {
        reasons.push('• *The user was marked `never-logon`.*');
      }

      if(ctx.meta.builtinAdmin) {
        reasons.push('• The user is a built-in adminstrator.');
      }

      if(ctx.meta.enterpriseAdmin) {
        reasons.push('• The user is an enterprise admin.');
      }
      else if(ctx.meta.domainAdmin) {
        reasons.push('• The user is a domain admin.');
      }

      if(reasons.length) {
        result.attachments.push({
          text: 'This alert was raised because:\n' + reasons.join('\n'),
          mrkdwn_in: ['text'],
          color: 'danger'
        });
      }

      return result;
    }
    else if(msg.msvistalog.system.eventId === 4771) {
      // 4771: Failed Kerberos preauth
      const targetArticle = getArticle(ctx, {sid: msg.log.target.sid});

      mainAttach.title = 'Kerberos preauthentication failure';
      mainAttach.color = 'danger';
      mainAttach.mrkdwn_in = ['text'];

      if(msg.msvistalog.logon.statusCode === 0x12) {
        mainAttach.fallback = `[Kerberos Preauth] Someone from ${slackEscape(msg.log.source.ip)} tried to log in as disabled user ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)}.`;
        mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* tried to log in as *disabled user* *${slackLinkToArticle(targetArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}*.`;
      }
      else if(msg.msvistalog.logon.statusCode === 0x6) {
        mainAttach.fallback = `[Kerberos Preauth] Someone from ${slackEscape(msg.log.source.ip)} tried to log in as invalid user ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)}.`;
        mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* tried to log in as *invalid user* *${slackLinkToArticle(targetArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}*.`;
      }
      else if(msg.msvistalog.logon.statusCode === 0x17) {
        mainAttach.fallback = `[Kerberos Preauth] ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)} tried to log in from ${slackEscape(msg.log.source.ip)} with an expired password.`;
        mainAttach.text = `*${slackLinkToArticle(targetArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}* tried to log in from *${slackEscape(msg.log.source.ip)}* with an *expired password*.`;
        mainAttach.color = 'warning';
      }
      else if(msg.msvistalog.logon.statusCode === 0x18) {
        mainAttach.fallback = `[Kerberos Preauth] Someone from ${slackEscape(msg.log.source.ip)} tried to log in as ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)} with an incorrect password.`;
        mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* tried to log in as *${slackLinkToArticle(targetArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}* with an *incorrect password*.`;
        mainAttach.color = 'warning';
      }
      else if(msg.msvistalog.logon.statusCode === 0x25) {
        mainAttach.fallback = `[Kerberos Preauth] Someone from ${slackEscape(msg.log.source.ip)} failed to log in as ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)} due to a large clock skew.`;
        mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* failed to log in as *${slackLinkToArticle(targetArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}* due to a large clock skew.`;
        mainAttach.color = 'warning';
      }
      else {
        mainAttach.fallback = `[Kerberos Preauth] Someone from ${slackEscape(msg.log.source.ip)} failed to log in as ${slackEscape(sourceIsDC && domain || hostname)}\\${slackEscape(msg.msvistalog.other.TargetUserName)} (status code ${msg.msvistalog.logon.statusCode}).`;
        mainAttach.text = `Someone from *${slackEscape(msg.log.source.ip)}* failed to log in as *${slackLinkToArticle(targetArticle, (sourceIsDC && domain || hostname) + '\\' + msg.msvistalog.other.TargetUserName)}* (status code ${msg.msvistalog.logon.statusCode}).`;
        mainAttach.color = 'warning';
      }

      const reasons = [];

      if(ctx.meta.neverLogon) {
        reasons.push('• *The user was marked `never-logon`.*');
      }

      if(ctx.meta.builtinAdmin) {
        reasons.push('• The user is a built-in adminstrator.');
      }

      if(ctx.meta.enterpriseAdmin) {
        reasons.push('• The user is an enterprise admin.');
      }
      else if(ctx.meta.domainAdmin) {
        reasons.push('• The user is a domain admin.');
      }

      if(reasons.length) {
        result.attachments.push({
          text: 'This alert was raised because:\n' + reasons.join('\n'),
          mrkdwn_in: ['text'],
          color: 'danger'
        });
      }

      return result;
    }
    else if(msg.msvistalog.system.eventId === 4781) {
      const sourceArticle = getArticle(ctx, {sid: msg.log.source.sid});

      // Account name change
      mainAttach.fallback = `${slackEscape(msg.log.source.samName)} renamed ${slackEscape(msg.msvistalog.other.OldTargetUserName)} to ${slackEscape(msg.msvistalog.other.NewTargetUserName)}.`;
      mainAttach.text = `${slackLinkToArticle(sourceArticle, msg.log.source.samName)} <http://wawa.com/|renamed> ${slackEscape(sourceIsDC && domain || hostname)}\\LOTSo to ${slackEscape(sourceIsDC && domain || hostname)}\\BELONgi.`;

      return result;
    }
  }

}

function slackLinkToArticle(article, fallbackText) {
  if(!article)
    return fallbackText && slackEscape(fallbackText);

  return `<https://localhost/investigator/wiki/article/${encodeURIComponent(article.id)}|${slackEscape(article.title)}>`;
}

function slackLinkToObj(ctx, refs) {
  const article = getArticle(ctx, refs);

  if(article)
    return slackLinkToArticle(article);

  return slackEscape(refs.fqdn || refs.samName || refs.sid);
}

function guessDomain(arg) {
  if(!arg)
    return null;

  const text = Array.isArray(arg) ? arg[0] : arg;
  const lower = text.toLowerCase();

  // You can add code here to make educated guesses about which
  // domain the argument refers to

  return null;
}

function guessFqdnDomain(text) {
  const domain = guessDomain(text);

  if(!domain)
    return null;

  return domain.fqdn;
}

function guessSamDomain(text) {
  const domain = guessDomain(text);

  if(!domain)
    return null;

  return domain.sam;
}

function guessDomainFromFqdn(fqdn) {
  // You can add code here to make educated guesses about which
  // domain the argument refers to
  return null;
}

function hostnameFromFqdn(fqdn) {
  const index = fqdn.indexOf('.');
  return index === -1 ? fqdn : fqdn.substring(0, index);
}

function getArticle(ctx, refs) {
  if(!ctx.wikiMap)
    return null;

  let articles;

  if(refs.sid) {
    let sid = Array.isArray(refs.sid) ? refs.sid[0] : refs.sid;
    articles = ctx.wikiMap.bySid.get(sid);

    if(articles)
      return articles[0];
  }

  if(refs.samName) {
    articles = ctx.wikiMap.bySamName.get(refs.samName.toUpperCase());

    if(articles)
      return articles[0];
  }

  if(refs.fqdn) {
    articles = ctx.wikiMap.byFqdn.get(refs.fqdn.toLowerCase());

    if(articles)
      return articles[0];
  }

  if(refs.ip) {
    articles = ctx.wikiMap.byIp.get(refs.ip);

    if(articles)
      return articles[0];
  }

  return null;
}

function first(arr) {
  if(Array.isArray(arr))
    return arr[0];

  return arr;
}
