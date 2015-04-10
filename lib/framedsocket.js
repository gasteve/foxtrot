'use strict';
var util = require('util');
var EventEmitter = require('events').EventEmitter;

function FramedSocket(socket, opts) {
  if(!(this instanceof FramedSocket)) return new FramedSocket(socket, opts); 
  this.socket = socket;
  this.buffer = new Buffer(0);
  this.mtu = (opts && opts.mtu) || 1000000; // default to 1mb for mtu
  bindEvents(this);
};
util.inherits(FramedSocket, EventEmitter);

var eventBindings = {
  "data": handleData,
  "error": handleError,
};

function bindEvents(inst) {
  for(var eventName in eventBindings) {
    inst.socket.on(eventName, eventBindings[eventName].bind(inst));
  }
};

function parse(inst, callback) {
  if(inst.buffer.length < 4) return callback();
  var len = inst.buffer.readUInt32LE(0);
  if(len > inst.mtu) return callback(new Error('packet size exceeds mtu'));
  if(inst.buffer.length < (len + 4)) return callback();
  var payload = inst.buffer.slice(4, len + 4);
  inst.buffer = inst.buffer.slice(len + 4);
  return callback(null, payload);
};

function handleData(data) {
  var self = this;
  if(self.buffer.length == 0) {
    self.buffer = data;
  } else {
    self.buffer = Buffer.concat([self.buffer, data], self.buffer.length + data.length);
  }
  var gotMessage = true;
  while(gotMessage) {
    parse(self, function(err, message) {
      if(err) self.emit('error', err);
      if(message) {
        self.emit('data', message);
      } else {
        gotMessage = false;
      }
    });
  }
};

function handleError(err) {
  this.emit('error', err);
};

FramedSocket.prototype.write = function(data, encoding, callback) {
  var framedBuf = new Buffer(data.length + 4);
  var offset = 0;
  framedBuf.writeUInt32LE(data.length, 0);
  data.copy(framedBuf, 4);
  this.socket.write(framedBuf, encoding, callback);
};

FramedSocket.prototype.end = function(data, encoding) {
  if(data) this.write(data, encoding);
  this.socket.end();
};

module.exports = FramedSocket;
