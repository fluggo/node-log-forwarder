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

const patterns = grok.loadDefaultSync();

patterns.createPattern('[^,]*', 'NONCOMMA');
patterns.createPattern('[^)]*', 'NONPAREN');
patterns.createPattern('[^\']*', 'NONSQUO');
patterns.createPattern('[^;,]*', 'NONSEMICOMMA');
patterns.createPattern('[A-Fa-f0-9]{12}', 'MAC_NOSEP');

// 311 <39>1 2016-12-19T22:12:49.3048546Z sysloghost CylancePROTECT - - - Event Type: Device, Event Name: SystemSecurity, Device Name: ***, Agent Version: 1.2.1400.39, IP Address: (10.0.0.1), MAC Address: (001122334455), Logged On Users: (), OS: Microsoft Windows 7 Professional Service Pack 1 x86 6.1.7601
const cylancePattern = patterns.createPattern('^%{NONNEGINT} <39>1 %{TIMESTAMP_ISO8601:eventTime} sysloghost CylancePROTECT - - - Event Type: %{NONCOMMA:eventType}, Event Name: %{NONCOMMA:eventName}, %{GREEDYDATA:message}');

// Event Type: Device, Event Name: SystemSecurity, Device Name: *****, Agent Version: 1.2.1400.39,
// IP Address: (10.0.0.1), MAC Address: (001122334455), Logged On Users: (), OS: Microsoft Windows 7 Professional Service Pack 1 x86 6.1.7601
const deviceSystemSecurity = patterns.createPattern('^Device Name: %{NONCOMMA:deviceName}, Agent Version: %{NONCOMMA:agentVersion}, IP Address: \\(%{NONPAREN:ipList}\\), MAC Address: \\(%{NONPAREN:macList}\\), Logged On Users: \\(%{NONPAREN:userList}\\), OS: %{GREEDYDATA:os}');

// Event Type: ExploitAttempt, Event Name: none, Device Name: *****, IP Address: (10.0.0.1), Action: None, Process ID: 24196, Process Name: C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\mscorsvw.exe, User Name: ***, Violation Type: Stack Protect, Zone Names: (***)
// ExploitAttempt/terminated, Device Name: ***, IP Address: (10.0.0.1), Action: Terminated, Process ID: 2960, Process Name: C:\Program Files (x86)\CMG\BR\2016.10\Win_x64\EXE\resgb.exe, User Name: ***, Violation Type: Overwrite Code, Zone Names: (***)
const exploitAttempt = patterns.createPattern('^Device Name: %{NONCOMMA:deviceName}, IP Address: \\(%{NONPAREN:ipList}\\), Action: %{NONCOMMA:action}, Process ID: %{NONNEGINT:processId}, Process Name: %{DATA:processName}, User Name: %{NONCOMMA:loginName}, Violation Type: %{NONCOMMA:violationType}, Zone Names: \\(%{NONPAREN:zoneList}\\)');

// Threat/corrupt_found: Device Name: ***, IP Address: (10.0.0.1), File Name: ysi.netclient[1].dll, Path: c:\users\***\appdata\local\microsoft\windows\temporary internet files\content.ie5\zob51z3k\, Drive Type: None, SHA256: 1A9A952FDC77EEB54CF855997C59F8543B6003C34991676B0263DA335577DFD1, MD5: , Status: Corrupt, Cylance Score: 0, Found Date: 1/3/2017 1:43:37 PM, File Type: Executable, Is Running: False, Auto Run: False, Detected By: FileWatcher, Zone Names: (***)
// ***, IP Address: (10.0.0.1), File Name: epgdatamanager.dll, Path: c:\program files\windowsapps\microsoft.xboxapp_24.24.20004.0_x64__8wekyb3d8bbwe\, Drive Type: None, SHA256: 6B70F0E634143C7314B04480FFF7084E4104E11080F10D40EB3D6243798A9633, MD5: , Status: Corrupt, Cylance Score: 0, Found Date: 1/7/2017 12:54:33 PM, File Type: Executable, Is Running: False, Auto Run: False, Detected By: FileWatcher, Zone Names: (***)
const threat = patterns.createPattern('^Device Name: %{NONCOMMA:deviceName}, IP Address: \\(%{NONPAREN:ipList}\\), File Name: %{DATA:fileName}, Path: %{DATA:path}, Drive Type: %{NONCOMMA:driveType}, SHA256: %{NONCOMMA:sha256}, MD5: %{NONCOMMA:md5}, Status: %{NONCOMMA:status}, Cylance Score: %{NONCOMMA:cylanceScore}, Found Date: %{NONCOMMA:foundDate}, File Type: %{NONCOMMA:fileType}, Is Running: %{NONCOMMA:isRunning}, Auto Run: %{NONCOMMA:autoRun}, Detected By: %{NONCOMMA:detectedBy}, Zone Names: \\(%{NONPAREN:zoneList}\\)');

// ThreatClassification/ThreatUpdated !!! Threat Class: PUP, Threat Subclass: Other, SHA256: 889AB82AE9D8419E77F36D7329A25FA1D76DBE6786CD95FDE3E166436EE86504, MD5: CCA486833AA3C3F5D34733B312286A71
const threatUpdated = patterns.createPattern('^Threat Class: %{DATA:threatClass}, Threat Subclass: %{DATA:threatSubClass}, SHA256: %{NONCOMMA:sha256}, MD5: %{NONCOMMA:md5}');

// AuditLog/DeviceEdit: Message: Device: ***; Policy Changed: 'policy_a' to 'policy_b'; Zones Removed: 'zone_a', User: ***
const auditLogGeneral = patterns.createPattern('^Message: %{DATA:messageText}, User: %{DATA:userName} \\(%{NONPAREN:userEmail}\\)');

// DeviceControl/fullaccess: Device Name: ***, External Device Type: USBDrive, External Device Vendor ID: 25FB, External Device Name: PENTAX PENTAX WG-3 USB Device, External Device Product ID: 0158, External Device Serial Number: 000001305101, Zone Names: (***)
const deviceControl = patterns.createPattern('^Device Name: %{NONCOMMA:deviceName}, External Device Type: %{NONCOMMA:externalDeviceType}, External Device Vendor ID: %{NONCOMMA:externalDeviceVendorId}, External Device Name: %{NONCOMMA:externalDeviceName}, External Device Product ID: %{NONCOMMA:externalDeviceProductId}, External Device Serial Number: %{NONCOMMA:externalDeviceSerialNumber}, Zone Names: \\(%{NONPAREN:zoneList}\\)');

const auditLoginSuccess = patterns.createPattern('^Provider: %{NONCOMMA:provider}, Source IP: %{NONCOMMA:ip}');
const auditDeviceEdit = patterns.createPattern('^Device: %{NONSEMICOMMA:deviceName}');
const auditDeviceRemoved = patterns.createPattern('^Devices: %{DATA:deviceList}');
const auditZoneRemoved = patterns.createPattern('^Zone: %{DATA:zoneList}; Devices: %{DATA:deviceList}');
const auditThreatSafeList = patterns.createPattern('^SHA256: %{NONSEMICOMMA:sha256}; Category: %{DATA:category}; Reason: %{DATA:reason}');
const auditThreatGlobalQuarantine = patterns.createPattern('^SHA256: %{NONSEMICOMMA:sha256}; Reason: %{DATA:reason}');
const auditThreatWaive = patterns.createPattern('^SHA256: %{NONSEMICOMMA:sha256}; Category: %{DATA:category}; Reason: %{DATA:reason}');
const auditPolicyEdit = patterns.createPattern('^%{DATA:policy}');
const deviceUpdated = patterns.createPattern('^Device Message: %{DATA:messageText}, User: %{DATA:userName} \\(%{NONPAREN:userEmail}\\)');
const deviceRemoved = patterns.createPattern('^Device Names: \\(%{NONPAREN:deviceList}\\), User: %{DATA:userName} \\(%{NONPAREN:userEmail}\\)');
const deviceRegistration = patterns.createPattern('^Device Name: %{NONCOMMA:deviceName}');

function preprocess(ctx, line) {
  return line;
}

function process(ctx, msg) {
  const parsed = cylancePattern.parseSync(msg);

  if(!parsed) {
    return {
      log: {
        reportingIp: ctx.meta.remoteAddress,
        receivingPort: ctx.meta.localPort,
        receivedTime: ctx.meta.receiveTime,
        message: msg,
        recordFinder: makeRecordFinder(),
        tag: ['cylance', 'failed-parse'],
      }
    };

    //console.log('!!! FAILED TO PARSE ' + line.log.message);
    //return;
  }

  const tags = new Set(['cylance']);

  var subParsed, auditParsed;

  if(parsed.eventType === 'AuditLog') {
    auditParsed = auditLogGeneral.parseSync(parsed.message);

    if(parsed.eventName === 'DeleteAllQuarantinedFiles')
      subParsed = auditDeviceEdit.parseSync(auditParsed.messageText);
    else if(parsed.eventName === 'LoginSuccess')
      subParsed = auditLoginSuccess.parseSync(auditParsed.messageText);
    else if(parsed.eventName === 'DeviceEdit') {
      //console.log(auditParsed.messageText);
      subParsed = auditDeviceEdit.parseSync(auditParsed.messageText);
    }
    else if(parsed.eventName === 'DeviceRemove') {
      subParsed = auditDeviceRemoved.parseSync(auditParsed.messageText);
    }
    else if(parsed.eventName === 'ZoneRemoveDevice') {
      subParsed = auditZoneRemoved.parseSync(auditParsed.messageText);
    }
    else if(parsed.eventName === 'ThreatSafeList') {
      subParsed = auditThreatSafeList.parseSync(auditParsed.messageText);
    }
    else if(parsed.eventName === 'PolicyEdit') {
      subParsed = auditPolicyEdit.parseSync(auditParsed.messageText);
    }
    else if(parsed.eventName === 'ThreatGlobalQuarantine') {
      subParsed = auditThreatGlobalQuarantine.parseSync(auditParsed.messageText);
    }

    if(!auditParsed || !subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }

    ctx.sendIrc('#cylance_audit');
  }
  else if(parsed.eventType === 'Device' && parsed.eventName === 'SystemSecurity') {
    subParsed = deviceSystemSecurity.parseSync(parsed.message);

    if(!subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }
  }
  else if(parsed.eventType === 'Device' && parsed.eventName === 'Device Updated') {
    subParsed = deviceUpdated.parseSync(parsed.message);

    if(!subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }
    else
      ctx.sendIrc('#cylance_device');
  }
  else if(parsed.eventType === 'Device' && parsed.eventName === 'Registration') {
    subParsed = deviceRegistration.parseSync(parsed.message);

    if(!subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }
    else
      ctx.sendIrc('#cylance_device');
  }
  else if(parsed.eventType === 'Device' && parsed.eventName === 'Device Removed') {
    subParsed = deviceRemoved.parseSync(parsed.message);

    if(!subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }
    else
      ctx.sendIrc('#cylance_device');
  }
  else if(parsed.eventType === 'ExploitAttempt') {
    subParsed = exploitAttempt.parseSync(parsed.message);

    tags.add('threat');

    if(!subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }
    else
      ctx.sendIrc('#cylance_threat');

    if(subParsed && subParsed.violationType === 'LSASS Read')
      ctx.sendIrc('#infosec_critical');
  }
  else if(parsed.eventType === 'ThreatClassification' && parsed.eventName === 'ThreatUpdated') {
    subParsed = threatUpdated.parseSync(parsed.message);

    tags.add('threat');

    if(!subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }
    else
      ctx.sendIrc('#cylance_threat');
  }
  else if(parsed.eventType === 'Threat') {
    subParsed = threat.parseSync(parsed.message);

    tags.add('threat');

    if(!subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }
    else {
      if(parsed.eventName !== 'corrupt_found')
        ctx.sendIrc('#cylance_threat');

      if(parsed.eventName === 'threat_quarantined' || parsed.eventName === 'threat_found')
        ctx.sendSlack('#cylance_threat');
    }
  }
  else if(parsed.eventType === 'ScriptControl') {
    /**** TODO ACTUALLY PARSE STUFF ****/

    tags.add('script');
    ctx.sendIrc('#cylance_script');
  }
  else if(parsed.eventType === 'DeviceControl') {
    subParsed = deviceControl.parseSync(parsed.message);

    tags.add('device-control');

    if(!subParsed) {
      tags.add('unparsed');
      ctx.sendIrc('#cylance_unparsed');
    }
    else
      ctx.sendIrc('#cylance_devicecontrol');
  }
  else {
    tags.add('unparsed');
    ctx.sendIrc('#cylance_unparsed');

    //console.error(`!!! Not yet parsed ${parsed.eventType}/${parsed.eventName} !!! ${parsed.message}`);
    //return;
  }

  const result = {
    log: {
      reportingIp: ctx.meta.remoteAddress,
      receivingPort: ctx.meta.localPort,
      receivedTime: ctx.meta.receiveTime,
      eventTime: new Date(parsed.eventTime),
      message: msg,
      source: {
        ip: subParsed && subParsed.ipList && subParsed.ipList.split(', '),
        mac: subParsed && subParsed.macList && subParsed.macList.split(', ').map(a => a.toLowerCase()),
        samName: subParsed && subParsed.userList && subParsed.userList.split(', ').map(a => a.toUpperCase()),
      },
      recordFinder: makeRecordFinder(),
      tag: tags,
    },
    cylance: {
      eventTime: new Date(parsed.eventTime),
      eventType: parsed.eventType,
      eventName: parsed.eventName,
      message: parsed.message,

      // Device SystemSecurity
      deviceName: subParsed && (subParsed.deviceList ? subParsed.deviceList.split(', ') : subParsed.deviceName),
      agentVersion: subParsed && subParsed.agentVersion,
      ip: subParsed && subParsed.ipList && subParsed.ipList.split(', '),
      mac: subParsed && subParsed.macList && subParsed.macList.split(', ').map(a => a.toLowerCase()),
      samName: subParsed && subParsed.userList && subParsed.userList.split(', ').map(a => a.toUpperCase()),

      // ExploitAttempt
      processId: subParsed && ((subParsed.processId !== undefined) ? +subParsed.processId : undefined),
      processName: subParsed && subParsed.processName,
      os: subParsed && subParsed.os,
      loginName: subParsed && subParsed.loginName,
      violationType: subParsed && subParsed.violationType,
      zone: subParsed && subParsed.zoneList && subParsed.zoneList.split(', '),

      // Threat
      fileName: subParsed && subParsed.fileName,
      fullPath: subParsed && subParsed.path && (subParsed.path + (subParsed.path.endsWith('\\') ? '' : '\\') + subParsed.fileName),
      driveType: subParsed && subParsed.driveType,
      sha256: subParsed && subParsed.sha256 && subParsed.sha256.toLowerCase(),
      md5: subParsed && subParsed.md5 && subParsed.md5.toLowerCase(),
      status: subParsed && subParsed.status,
      cylanceScore: subParsed && ((subParsed.cylanceScore !== undefined) ? +subParsed.cylanceScore : undefined),
      //foundDate: new Date(subParsed.foundDate),   // Leaving out because time zone is unclear, could be CT
      fileType: subParsed && subParsed.fileType,
      isRunning: subParsed && ((subParsed.isRunning !== undefined) ? subParsed.isRunning !== 'False' : undefined),
      autoRun: subParsed && ((subParsed.autoRun !== undefined) ? subParsed.autoRun !== 'False' : undefined),
      detectedBy: subParsed && subParsed.detectedBy,
      threatClass: subParsed && subParsed.threatClass,
      threatSubClass: subParsed && subParsed.threatSubClass,

      // AuditLog
      provider: subParsed && subParsed.provider,
      userName: subParsed && (subParsed.userName || (auditParsed && auditParsed.userName)),
      userEmail: subParsed && (subParsed.userEmail || (auditParsed && auditParsed.userEmail)),
      auditMessage: auditParsed && auditParsed.messageText,
      category: subParsed && subParsed.category,
      reason: subParsed && subParsed.reason,
      policy: subParsed && subParsed.policy,
    }
  };

  const externalDevice = {
    type: subParsed && subParsed.externalDeviceType,
    vendorId: subParsed && subParsed.externalDeviceVendorId,
    name: subParsed && subParsed.externalDeviceName,
    productId: subParsed && subParsed.externalDeviceProductId,
    serialNumber: subParsed && subParsed.externalDeviceSerialNumber,
  };

  if(externalDevice.type)
    result.cylance.externalDevice = externalDevice;

  result.log.tag = Array.from(result.log.tag);

  const buffer = Buffer.allocUnsafe(8);
  buffer.writeUIntLE(new Date(result.log.receivedTime).getTime(), 0, 8);

  ctx.meta.finderUrl = 'https://localhost/investigator/?cy=' + encodeURIComponent(shortenBase64(buffer.toString('base64')) + '-' + result.log.recordFinder);
  ctx.sendElasticsearch('cylancelog-' + dateFormat(result.log.receivedTime), 'cylancelog');
  ctx.sendFile(`cylance/${fileDateFormat(new Date(result.log.receivedTime))}/cylance-${localHourFormat(new Date(result.log.receivedTime))}.jsonlog`);

  return result;
}


/****** IRC ******/

function ellipsify(str, length) {
  if(str.length > length)
    return str.substring(0, length - 3) + '...';

  return str;
}

function ircEscape(str) {
  return str.replace(/[\x00-\x1f]/g, ' ');
}

function stringArray(str) {
  if(!str)
    return '(unknown)';

  if(Array.isArray(str))
    return str.join(', ');

  return str;
}

function makeIrcMessage(ctx, msg) {
  if(msg.cylance.eventType === 'ExploitAttempt') {
    return `Running as ${ircEscape(stringArray(msg.cylance.loginName))} on ${ircEscape(stringArray(msg.cylance.deviceName))}; "${ircEscape(msg.cylance.violationType)}" violation from process ${ircEscape(msg.cylance.processName)}`;
  }
  else if(msg.log.message) {
    return ircEscape(msg.cylance.message);
  }
}

function formatIrc(ctx, msg) {
  var str = '';

  if(msg.cylance.eventType === 'Threat') {
    // White text on red background
    str += '\x0300,04 THREAT \x03 ';

    if(msg.cylance.eventName === 'corrupt_found') {
      // White text on orange background
      str += '\x0300,07 Corrupt file \x03 ';
    }
    else {
      str += `\x0300,07 ${msg.cylance.eventName} \x03 `;
    }
  }
  else if(msg.cylance.eventType === 'ExploitAttempt') {
    // White text on red background
    str += '\x0300,04 Exploit attempt \x03 ';

    if(msg.cylance.eventName === 'terminated') {
      // White text on red background
      str += '\x0300,04 Terminated \x03 ';
    }
    else {
      str += `\x0300,07 ${msg.cylance.eventName} \x03 `;
    }
  }
  else if(msg.cylance.eventType === 'AuditLog') {
    // White text on green background
    str += `\x0300,03 AuditLog \x03 `;

    // Black text on light gray background
    str += `\x0301,15 ${msg.cylance.eventName} \x03 `;
  }
  else {
    // Black text on light gray background
    str += `\x0301,15 ${msg.cylance.eventType} \x03 `;
    str += `\x0301,15 ${msg.cylance.eventName} \x03 `;
  }

  str += ellipsify(makeIrcMessage(ctx, msg), 200) + '\x0f';

/*  const addlInfo = [];

  //if(msg.wsa.request.username)
  //  addlInfo.push('as ' + ircEscape(msg.wsa.request.samName || msg.wsa.request.username));

  addlInfo.push(msg.msvistalog.system.eventId + '');

  if(msg.msvistalog.system.taskName)
    addlInfo.push('"' + ircEscape(msg.msvistalog.system.taskName) + '"');

  if(msg.msvistalog.system.computer)
    addlInfo.push('from ' + ircEscape(msg.msvistalog.system.computer));

  if(addlInfo.length)
    str += ' \x0314(' + addlInfo.join(' ') + ')';*/

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
  const result = {
    username: 'Cylance',
    attachments: [
      {
        fallback: null,
        color: 'warning',
        text: null,
        ts: msg.log.eventTime.getTime() * 0.001,
      }
    ]
  };

  const mainAttach = result.attachments[0];

  if(msg.cylance.eventType === 'Threat') {
    if(msg.cylance.eventName === 'threat_quarantined') {
      mainAttach.fields = [{ title: 'Path', value: msg.cylance.fullPath }];
      mainAttach.fallback = `Cylance quarantined a file on ${slackEscape(first(msg.cylance.deviceName))}: ${slackEscape(msg.cylance.fullPath)}`;
      mainAttach.text = `Cylance <${ctx.meta.finderUrl}|quarantined> a file on ${slackEscape(first(msg.cylance.deviceName))}. (<https://www.virustotal.com/en/file/${msg.cylance.sha256 || msg.cylance.md5}/analysis/|VirusTotal>)`;
      mainAttach.title = ':skull_and_crossbones: Threat quarantined';

      return result;
    }
    else if(msg.cylance.eventName === 'threat_found') {
      mainAttach.fields = [{ title: 'Path', value: msg.cylance.fullPath }];
      mainAttach.fallback = `Cylance found a file on ${slackEscape(first(msg.cylance.deviceName))}: ${slackEscape(msg.cylance.fullPath)}`;
      mainAttach.text = `Cylance <${ctx.meta.finderUrl}|found> a file on ${slackEscape(first(msg.cylance.deviceName))}. (<https://www.virustotal.com/en/file/${msg.cylance.sha256 || msg.cylance.md5}/analysis/|VirusTotal>)`;
      mainAttach.title = ':rotating_light: Threat found';

      return result;
    }
  }

}

function first(arr) {
  if(Array.isArray(arr))
    return arr[0];

  return arr;
}
