'use strict';
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var bitcore = require('bitcore');
var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;
var sha256 = bitcore.crypto.Hash.sha256;
var Message = bitcore.Message;
var ECIES = require('bitcore-ecies');
var Random = bitcore.crypto.Random;
var crypto = require('crypto');
var AESSocket = require('./AESSocket');

var shastring = require('./shastring');
var MAGIC = 'v0001';
var MAGIC_BUF = new Buffer(MAGIC);

var STATE_NEW = 'new';
var STATE_WAIT_MAGIC = 'wait_magic';
var STATE_WAIT_PUBKEY = 'wait_pubkey';
var STATE_WAIT_PREMASTER = 'wait_premaster';
var STATE_WAIT_OK = 'wait_ok';
var STATE_READY = 'ready';

function NOOP() {};

function KeyExchanger(transport) {
  if(!(this instanceof KeyExchanger)) return new KeyExchanger(transport);
  var self = this;
  this.state = STATE_NEW;
  this.key = PrivateKey(); // eckey for exchange of session key
  this.ecies = ECIES({noKey: true, shortTag: true});
  this.aesSocket = AESSocket(transport);
  var parser = shastring.Parser();
  this.aesSocket.parser = parser;
  this.messageHandler = NOOP;
  this.transport = transport;
  transport.on('data', parser.processData.bind(parser));
  this.parserDataHandler = (function(data) {
    this.messageHandler(null, data);
  }).bind(this);
  this.parserErrorHandler = (function(err) {
    this.transport.close();
    this.messageHandler(err);
  }).bind(this);
  parser.on('data', this.parserDataHandler);
  parser.on('error', this.parserErrorHandler);
};
util.inherits(KeyExchanger, EventEmitter);

KeyExchanger.prototype.parserDataHandler = function(data) {
  this.messageHandler(null, data);
};

KeyExchanger.prototype.parserErrorHandler = function(err) {
  this.transport.close();
  this.messageHandler(err);
};

KeyExchanger.prototype.handoffToSocket = function() {
  this.aesSocket.parser.removeListener('data', this.parserDataHandler);
  this.aesSocket.parser.removeListener('error', this.parserErrorHandler);
  this.aesSocket.bindParser();
};

KeyExchanger.prototype.clientHandshake = function(callback) {
  var self = this;
  this.transport.write(shastring(MAGIC_BUF));
  this.transport.write(shastring(this.key.publicKey.toDER()));
  this.expectServerPubkey(function(err, pubkey) {
    if(err) return callback(err);
    self.ecies.publicKey(pubkey);
    self.transport.write(shastring(self.encrypt(new Buffer('OK'))));
    self.expectOK(function(err) {
      if(err) return callback(err);
      self.messageHandler = NOOP;
      self.state = STATE_READY;
      self.handoffToSocket();
      callback(null, self.aesSocket); 
    });  
  });
};

KeyExchanger.prototype.serverHandshake = function(callback) {
  var self = this;
  self.expectMagic(function(err) {
    if(err) return callback(err);
    self.expectClientPubkey(function(err, pubkey) {
      if(err) return callback(err);
      var myPubKeyEncrypted = ECIES().privateKey(self.key).publicKey(PublicKey.fromBuffer(pubkey)).encrypt(self.key.publicKey);
      self.transport.write(shastring(myPubKeyEncrypted));
      self.encryptedSocket.privateKey(self.key);
      self.encryptedSocket.publicKey(pubkey);
      self.transport.write(shastring(self.encrypt(new Buffer('OK'))));
      self.expectOK(function(err) {      
        if(err) return callback(err);
        self.messageHandler = NOOP;
        self.state = STATE_READY;
        self.handoffToSocket();
        callback(null, self.aesSocket);
      });
    });
  });
};

KeyExchanger.prototype.expect = function(state, handler) {
  this.state = state;
  this.messageHandler = function(err, message) {
    this.messageHandler = NOOP;
    handler(err, message);
  };
};

KeyExchanger.prototype.expectOK = function(callback) {
  var self = this;
  this.expect(STATE_WAIT_OK, function(err, message) {
    if(err) return callback(err);
    if(self.decrypt(message).toString() == 'OK') {
      callback();
    } else {
      callback(new Error('expected OK'));
    }
  });
};

KeyExchanger.prototype.expectPreMasterKey = function(callback) {
  this.expect(STATE_WAIT_PREMASTER, function(err, message) {
    callback(err, message);
  });
};

KeyExchanger.prototype.expectMagic = function(callback) {
  this.expect(STATE_WAIT_MAGIC, function(err, message) {
    if(message != MAGIC) return callback(new Error('no magic'));
    callback(err);
  });
};

KeyExchanger.prototype.expectClientPubkey = function(callback) {
  this.expect(STATE_WAIT_PUBKEY, function(err, message) {
    if(err) return callback(err);
    if(message.length != 33) return callback(new Error('invalid public key from client'));
    callback(null, PublicKey.fromDER(message));
  });
};

KeyExchanger.prototype.expectServerPubkey = function(callback) {
  var self = this;
  this.expect(STATE_WAIT_PUBKEY, function(err, message) {
    if(err) return callback(err);
    try {
      var serverPubKey = ECIES.decrypt(self.key.private, message);
    } catch(e) {
      return callback(e);
    }
    callback(null, serverPubKey);
  });
};

KeyExchanger.prototype.encrypt = function(message) {
  return this.aesSocket.encrypt(message);
};

KeyExchanger.prototype.decrypt = function(message) {
  return this.aesSocket.decrypt(message);
};

module.exports = KeyExchanger;
