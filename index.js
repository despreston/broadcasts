const dgram = require('dgram');
const client = dgram.createSocket('udp4');
const server = dgram.createSocket('udp4');
const Packet = require('./packet');
const port = 67;
const address = '0.0.0.0';

client.on('message', ( msg, rinfo ) => {
  console.log( Packet( msg ).toString() );
  console.log('');
});

client.on('listening', () => {
  console.log( 'listening', client.address() );
});

client.bind(port, address);
