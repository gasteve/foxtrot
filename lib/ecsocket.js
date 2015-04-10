var util = require('util');
var bitcore = require('bitcore');
var EventEmitter = require('events').EventEmitter;
var ECIES = require('bitcore-ecies');
var PrivateKey = bitcore.PrivateKey;
var PublicKey = bitcore.PublicKey;

var MAGIC = 'T70s';
var MAGIC_BUF = new Buffer(MAGIC);

function ECSocket(socket, privateKey) {
  if(!(this instanceof ECSocket)) return new ECSocket(socket, privateKey);
  var self = this;
  self.socket = socket;
  self.ecies = ECIES({noKey: true, shortTag: true});
  self.ecies.privateKey(privateKey || PrivateKey());
  handshake(self, function(err) {
    if(err) return self.emit('error', err)
    bindEvents(self);
    self.emit('connect');
  });
};
util.inherits(ECSocket, EventEmitter);

var eventBindings = {
  "data": handleData,
  "error": handleError,
// need to also handle/emit the following standard socket events
//   lookup, connect, end, timeout, drain, close
};

function bindEvents(self) {
  for(var eventName in eventBindings) {
    self.socket.on(eventName, eventBindings[eventName].bind(self));
  }
};

function handleData(data) {
  this.emit('data', this.ecies.decrypt(data));
};

function handleError(error) {
  this.emit('error', error);
};

/**
 *  Internal function to perform a handshake with the other end.  Each step is factored into its own method for the sake of clarity when trying to read and understand the protocol.  On success, the connect event is emitted.
 *
 *  @param {ECSocket} the instance on which the handshake is performed
 *  @param {Function} callback function
 */
function handshake(self, callback) {
  sendMagic(self);
  sendPublicKey(self);
  expectMagic(self, function(err) {
    if(err) return callback(err);
    expectPublicKey(self, function(err, correspondentPublicKey) {
      if(err) return callback(err);
      setPublicKey(self, correspondentPublicKey);
      self.ecies.publicKey(correspondentPublicKey);
      sendOk(self);
      expectOk(self, callback);
    });
  });
};

function sendMagic(self) {
  self.socket.write(MAGIC_BUF);
};

function sendPublicKey(self) {
  self.socket.write(self.ecies._privateKey.publicKey.toDER());
};

function sendOk(self) {
  self.socket.write(self.ecies.encrypt('OK'));
};

function setPublicKey(self, correspondentPublicKey) {
  self.ecies.publicKey(correspondentPublicKey);
};

function readData(self, callback) {
  // need to handle other events here to ensure all 
  // error and socket clousure cases are handled
  function handleData(data) {
    self.socket.removeListener('data', handleData);
    callback(data);
  }
  self.socket.on('data', handleData);
};

function expectMagic(self, callback) {
  readData(self, function(data) {
    if(data.toString() != MAGIC) return callback(new Error('no magic'));
    callback();
  });
};

function expectPublicKey(self, callback) {
  readData(self, function(data) {
    if(data.length != 33) return callback(new Error('invalid public key'));
    callback(null, PublicKey.fromDER(data));
  });
};

function expectOk(self, callback) {
  readData(self, function(data) {
    var message = self.ecies.decrypt(data).toString();
    if(message != 'OK') return callback(new Error('expected OK'));
    callback();
  });
};

/**
 * Sends data on the socket. The second parameter specifies the encoding in the case of a string--it defaults to UTF8 encoding.  Returns true if the entire data was flushed successfully to the kernel buffer. Returns false if all or part of the data was queued in user memory. 'drain' will be emitted when the buffer is again free.  The optional callback parameter will be executed when the data is finally written out - this may not be immediately.
 *
 * @param {*} data
 * @param {Object} encoding
 * @param {Function} callback
 * @returns {Boolean} Returns true if the entire data was flushed successfully to the kernel buffer. Returns false if all or part of the data was queued in user memory. 'drain' will be emitted when the buffer is again free.
 */
ECSocket.prototype.write = function(data, encoding, callback) {
  if(typeof encoding == 'function') {
    callback = encoding;
    encoding = undefined;
  }
  if(typeof data == 'string') data = new Buffer(data, encoding);
  return this.socket.write(this.ecies.encrypt(data), callback);
};

ECSocket.prototype.end = function(data, encoding) {
  if(data) this.write(data, encoding);
  this.socket.end();
};

module.exports = ECSocket;
