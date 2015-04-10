var should = require('chai').should();
var SimSocket = require('./util/Socket');
var FramedSocket = require('../lib/framedsocket');
var ECSocket = require('../lib/ecsocket');

describe('ecsocket', function() {
  var pair;
  beforeEach(function() {
    pair = SimSocket.createPair();
  });
  it('should emit a connect event', function(done) {
    var alice = ECSocket(FramedSocket(pair[0]));
    var bob = ECSocket(FramedSocket(pair[1]));
    var aliceIsConnected = false;
    var bobIsConnected = false;
    alice.on('connect', function() {
      aliceIsConnected = true;
      if(bobIsConnected) done();
    });
    bob.on('connect', function() {
      bobIsConnected = true;
      if(aliceIsConnected) done();
    });
  });
  it('should encrypt and decrypt data', function(done) {
    var alice = ECSocket(FramedSocket(pair[0]));
    var bob = ECSocket(FramedSocket(pair[1]));
    alice.on('connect', function() {
      alice.write('this is a test');
    });
    bob.on('data', function(data) {
      data.toString().should.equal('this is a test');
      done(); 
    });
  });
});
