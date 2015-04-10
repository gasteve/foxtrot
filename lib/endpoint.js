var util = require('util');
var EventEmitter = require('events').EventEmitter;

var bitcore = require('bitcore');
var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;
var ECIES = require('bitcore-ecies');
var Message = require('bitcore-message');

function Endpoint(key) {
  if(!(this instanceof Endpoint)) return new Endpoint(key);
  this.key = key || PrivateKey();
};
util.inherits(Endpoint, EventEmitter);

Endpoint.prototype.credentials = function(request) {
  var signature = Message(Buffer.concat([request.address, request.nonce]).toString())._sign(this.key);
  var msg = Buffer.concat([this.key.publicKey.toBuffer(), new Buffer(signature)]);
  
  return ECIES().privateKey(this.key).publicKey(PublicKey.fromDER(request.address)).encrypt(signature.toCompact());
};

Endpoint.prototype.isMatch = function(pubkey) {
  return this.key.publicKey.toString() == pubkey.toString();
};

module.exports = Endpoint;
