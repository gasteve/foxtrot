var should = require('chai').should();
var FramedSocket = require('../lib/framedsocket');
var SimSocket = require('./util/Socket');

describe('FramedSocket', function() {
  var alice, bob;

  beforeEach(function() {
    var socketPair = SimSocket.createPair();
    alice = FramedSocket(socketPair[0]);
    bob = FramedSocket(socketPair[1]);
  });
  it('should encode and decode a string', function(done) {
    bob.on('data', function(data) {
      data.toString().should.equal('foo');
      done();
    });
    alice.write(new Buffer('foo'));
  });
  it('should handle misaligned data', function(done) {
    var aliceRaw = alice.socket;
    bob.on('data', function(data) {
      data.toString().should.equal('this is mis-aligned');
      done();
    });
    var lenbuf = new Buffer(4);
    lenbuf.writeUInt32LE(19, 0);
    aliceRaw.write(lenbuf.slice(0,2));
    aliceRaw.write(lenbuf.slice(2));
    aliceRaw.write(new Buffer('this is mi'));
    aliceRaw.write(new Buffer('s-aligned'));
  });
});
