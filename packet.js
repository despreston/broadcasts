const fs = require('fs');
const ipv4 = data => [ ...data.entries() ].map( entry => entry[ 1 ] ).join('.');
const str = data => data.toString().replace(/\u0000/g, '');

const mac = data => [ ...data ]
  .filter( shit => !!shit )
  .map( shit => shit.toString( 16 ) ).join(':');

const optionsLookup = {
  1:  data => ( { SubnetMask: ipv4( data ) } ),
  3:  data => ( { Router: ipv4( data ) } ),
  6:  data => ( { DNS: ipv4( data ) } ),
  15: data => ( { Domain: str( data ) } ),
  44: data => ( { NBNS: ipv4( data ) } ),
  51: data => ( { LeaseTime: data.readUInt32BE() } ),
  53: data => ( { MessageType: data.readUInt8() } ),
  54: data => ( { ServerIdentifier: ipv4( data ) } ),
  55: data => ( { Parameters: data } ),
  56: data => ( { Message: str( data ) } ),
  58: data => ( { RenewalTime: data.readUInt32BE() } ),
  59: data => ( { RebindingTime: data.readUInt32BE() } )
};

function loadOptions () {
  try {
    const optionsFile = fs.readFileSync('options.csv', 'utf8');

    let optionsArray = optionsFile.split('\n').reduce( ( arr, option ) => {
      return arr.concat([ option.split(',') ]);
    }, []);

    optionsArray.splice( 0, 1 );

    optionsArray.forEach( ( [ code, name ] ) => {
      if( !optionsLookup[ code ] ) {
        optionsLookup[ code ] = data => ( { [ name ] : str( data ) } );
      }
    });

  } catch ( err ) {
    console.log('Problem opening options.csv');
  }
}

loadOptions();

class Packet {

  constructor( msg ) {
    this.msg = Buffer.from( msg );

    this.data = {
      'op': 0,
      'htype': 0,
      'hlen': 0,
      'hops': 0,
      'xid': 0,
      'secs': 0,
      'flags': 0,
      'ciaddr': '',
      'yiaddr': '',
      'siaddr': '',
      'giaddr': '',
      'chaddr': '',
      'sname': '',
      'file': '',
      'magic': '',
      'options': []
    };

    this.parse();
  }

  toString() {
    const fields = Object.keys( this.data );

    const output = fields.reduce( ( str, field ) => {
      let value = this.data[ field ];

      if ( field === 'magic' ) {
        return str;
      }

      if ( field === 'options' && value ) {
        value = JSON.stringify( value );
      }

      return `${str}\n${field}: ${value}`;
    }, '' );

    return output;
  }

  parse() {
    this.data.op      = this.msg.readUInt8( 0 );
    this.data.htype   = this.msg.readUInt8( 1 );
    this.data.hlen    = this.msg.readUInt8( 2 );
    this.data.hops    = this.msg.readUInt8( 3 );
    this.data.xid     = this.msg.readUInt32BE( 4 );
    this.data.secs    = this.msg.readUInt16BE( 8 );
    this.data.flags   = this.msg.readUInt16BE( 10 );
    this.data.ciaddr  = ipv4( this.msg.slice( 12, 12 + 4 ) );
    this.data.yiaddr  = ipv4( this.msg.slice( 16, 16 + 4 ) );
    this.data.siaddr  = ipv4( this.msg.slice( 20, 20 + 4 ) );
    this.data.giaddr  = ipv4( this.msg.slice( 24, 24 + 4 ) );
    this.data.chaddr  = mac( this.msg.slice( 28, 28 + 16 ) );
    this.data.sname   = this.msg.slice( 44, 44 + 64 ).toString();
    this.data.file    = this.msg.slice( 108, 108 + 128 ).toString();
    this.data.magic   = this.msg.slice( 236, 236 + 4 );
    this.data.options = this.parseOptions();
  }

  parseOptions() {
    let parsed = [];
    let offset = 240;
    let type;
    let length;
    let data;

    while ( type !== 0xff && offset < this.msg.length ) {
      type = this.msg[ offset ];
      offset += 1;

      if ( type === 0xff ) {
        break;
      }

      if ( type === 0x00 ) {
        offset += 1;
        break;
      }

      length = this.msg.readUInt8( offset );
      offset += 1;
      data = this.msg.slice( offset, offset = offset + length );

      if ( optionsLookup[ type ] ) {
        data = optionsLookup[ type ]( data );
        data.Code = type;
        parsed.push( data );
      }
    }

    return parsed;
  }

}

module.exports = ( ...args ) => new Packet( ...args );
