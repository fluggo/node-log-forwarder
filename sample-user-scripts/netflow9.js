'use strict';

const d3 = require('d3');
const dateFormat = d3.timeFormat('%Y.%m.%d');
const fileDateFormat = d3.timeFormat('%Y-%m-%d');
const localHourFormat = d3.timeFormat('%H');

function preprocess(ctx, msg) {
  if(ctx.meta.netflowVersion !== 9)
    return;

  return msg;
}

function process(ctx, flow) {
  const result = {};

  // Set reporting ip
  result.reporting_ip = ctx.meta.remoteAddress;

  // Set times
  if(flow.last_switched)
    result.last_switched = new Date(flow.last_switched - ctx.meta.packetHeader.uptime + ctx.meta.packetHeader.seconds * 1000);

  if(flow.first_switched)
    result.first_switched = new Date(flow.first_switched - ctx.meta.packetHeader.uptime + ctx.meta.packetHeader.seconds * 1000);

  if(flow.observationTimeMilliseconds)
    result.observationTime = new Date(flow.observationTimeMilliseconds);

  if(flow.flowStartMilliseconds)
    result.flowStart = new Date(flow.flowStartMilliseconds);

  result.startTime = result.first_switched || result.flowStart || result.observationTime;
  result['@timestamp'] = new Date(result.last_switched || result.observationTime || result.first_switched || result.flowStart);
  result.receivedTime = ctx.meta.receivedTime;

  // If they didn't give us a time, don't even try
  if(isNaN(result['@timestamp'].getTime()))
    return;

  ctx.sendElasticsearch('netflow-' + dateFormat(result['@timestamp']), 'netflow9')
  ctx.sendFile(`${ctx.meta.remoteAddress}/${fileDateFormat(result['@timestamp'])}/netflow9-${localHourFormat(result['@timestamp'])}.jsonlog`);

  if(flow.protocol === 6 && flow.tcp_flags !== undefined) {
    result.tcp_flags = {
      urg: (flow.tcp_flags & 0x20) !== 0,
      ack: (flow.tcp_flags & 0x10) !== 0,
      psh: (flow.tcp_flags & 0x08) !== 0,
      rst: (flow.tcp_flags & 0x04) !== 0,
      syn: (flow.tcp_flags & 0x02) !== 0,
      fin: (flow.tcp_flags & 0x01) !== 0,
    };
  }

  // Copy remaining fields
  Object.keys(flow).forEach(function(key) {
    // Ignore unknown fields
    if(key.startsWith('unknown_type_'))
      return;

    // Drop ICMP fields for non-ICMP
    if((key === 'icmpTypeIPv4' || key === 'icmpCodeIPv4') && flow.protocol !== 1)
      return;

    // We dealt with these already
    if(key === 'last_switched' || key === 'first_switched' || key === 'observationTimeMilliseconds'
        || key === 'flowStartMilliseconds' || key === 'tcp_flags')
      return;

    result[key] = flow[key];
  });

  return result;
}
