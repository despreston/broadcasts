const ipv4 = data => [ ...data.entries() ].map( entry => entry[ 1 ] ).join('.');

const mac = data => [ ...data ]
  .filter( shit => !!shit )
  .map( shit => shit.toString( 16 ) ).join(':');

const options = {
  /**
   * Subnet Mask
   */
  1: data => ( { SubnetMask: ipv4( data ) } ),
  /**
   * Router Option
   */
  3: data => ( { Router: ipv4( data ) } ),
  /**
   * DNS
   */
  6: data => ( { DNS: ipv4( data ) } ),
  15: data => ( { Domain: data.toString() } ),
  44: data => ( { NBNS: ipv4( data ) } ),
  51: data => ( { LeaseTime: data.readUInt32BE() } ),
  53: data => ( { MessageType: data.readUInt8() } ),
  54: data => ( { ServerIdentifier: ipv4( data ) } ),
  55: data => ( { Parameters: data } ),
  56: data => ( { Message: data.toString() } ),
  58: data => ( { RenewalTime: data.readUInt32BE() } ),
  59: data => ( { RebindingTime: data.readUInt32BE() } )
};

class Packet {

  constructor( msg ) {
    this.msg     = Buffer.from( msg );
    this.op      = 0;
    this.htype   = 0;
    this.hlen    = 0;
    this.hops    = 0;
    this.xid     = 0;
    this.secs    = 0;
    this.flags   = 0;
    this.ciaddr  = '';
    this.yiaddr  = '';
    this.siaddr  = '';
    this.giaddr  = '';
    this.chaddr  = '';
    this.sname   = '';
    this.file    = '';
    this.options = [];

    this.parse();
  }

  toString() {
    const fields = [
      'op',
      'htype',
      'hlen',
      'hops',
      'xid',
      'secs',
      'flags',
      'ciaddr',
      'yiaddr',
      'siaddr',
      'giaddr',
      'chaddr',
      'sname',
      'file',
      'options'
    ];

    const output = fields.reduce( ( str, field ) => {
      let value = this[ field ];

      if ( field === 'options' && value ) {
        value = JSON.stringify( value );
      }

      return `${str}\n${field}: ${value}`;
    }, '' );

    return output;
  }

  parse() {
    this.op     = this.msg.readUInt8( 0 );
    this.htype  = this.msg.readUInt8( 1 );
    this.hlen   = this.msg.readUInt8( 2 );
    this.hops   = this.msg.readUInt8( 3 );
    this.xid    = this.msg.readUInt32BE( 4 );
    this.secs   = this.msg.readUInt16BE( 8 );
    this.flags  = this.msg.readUInt16BE( 10 );
    this.ciaddr = ipv4( this.msg.slice( 12, 12 + 4 ) );
    this.yiaddr = ipv4( this.msg.slice( 16, 16 + 4 ) );
    this.siaddr = ipv4( this.msg.slice( 20, 20 + 4 ) );
    this.giaddr = ipv4( this.msg.slice( 24, 24 + 4 ) );
    this.chaddr = mac( this.msg.slice( 28, 28 + 16 ) );
    this.sname  = this.msg.slice( 44, 44 + 64 ).toString();
    this.file   = this.msg.slice( 108, 108 + 128 ).toString();
    this.magic  = this.msg.slice( 236, 236 + 4 );
    this.options = this.parseOptions();
  }

  parseOptions() {
    let offset = 240;
    let type;
    let length;
    let data;

    while ( type !== 0xff && offset < this.msg.length ) {
      offset += 1;
      type = this.msg[ offset ];

      if ( type === 0xff ) {
        break;
      }

      offset += 1;

      if ( type === 0x00 ) {
        break;
      }

      length = this.msg.readUInt8( offset );
      data = this.msg.slice( offset, offset = offset + length );

      if ( typeof options[ type ] === 'function' ) {
        data = options[ type ]( data );
        data.Code = type;
        this.options = this.options.concat( data );
      } else {
        this.options = this.options.concat( {
          Code: type,
          data
        } );
      }
    }
  }

}

module.exports = ( ...args ) => new Packet( ...args );
