const dgram = require('dgram');
const socket = dgram.createSocket('udp4');
const Packet = require('./packet');

socket.on('message', (msg, rinfo) => {
  console.log( Packet( msg ).toString() );
});

socket.on('listening', () => {
  console.log('listening', socket.address())
})

socket.bind(67, '0.0.0.0');
