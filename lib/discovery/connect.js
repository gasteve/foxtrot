var net = require('net');
var Peer = require('../Peer');
var sha256ripemd160 = require('bitcore').crypto.Hash.sha256ripemd160;
var ECSocket = require('../ecsocket');
var FramedSocket = require('../framedsocket');

function tcpconnect(router, options) {
  var tcpSocket = net.connect(options, function() {
    var ecSocket = ECSocket(FramedSocket(tcpSocket));
    ecSocket.on('connect', function() {
      var peer = Peer(ecSocket, router);
      var timer;
      var handler = function(message) {
        if(message.name == 'VERSION') {
          peer.version = message.version;
          peer.id = message.identity;
          peer.VERACK();
        }
        if(message.name == 'VERACK') {
          clearTimeout(timer);
          peer.removeListener('message', handler);
          router.addPeer(peer);
        }
      };
      timer = setTimeout(function() {
        peer.removeListener('message', handler);
      }, 3000);
      peer.on('message', handler);
      var identity = sha256ripemd160(router.key.publicKey.toDER());
      peer.VERSION(new Buffer(4), new Buffer('foo'), identity, new Buffer(8), new Buffer(8), new Buffer(8), new Buffer(26), new Buffer(26));
    });
    ecSocket.on('error', function(err) {
      trace(err);
    });
  });

/*
    var keyExchanger = KeyExchanger(tcpSocket);
    keyExchanger.clientHandshake(function(err, socket) {
      if(err) {
        trace(err);
      } else {
        var peer = Peer(socket, router);
        var timer;
        var handler = function(message) {
          if(message.name == 'VERSION') {
            peer.version = message.version;
            peer.id = message.identity;
            peer.VERACK();
          }
          if(message.name == 'VERACK') {
            clearTimeout(timer);
            peer.removeListener('message', handler);
            router.addPeer(peer);
          }
        }
        timer = setTimeout(function() {
          peer.removeListener('message', handler);
        }, 3000);
        peer.on('message', handler);
        var identity = sha256ripe160(router.key.public);
        peer.VERSION(new Buffer(4), new Buffer('foo'), identity, new Buffer(8), new Buffer(8), new Buffer(8), new Buffer(26), new Buffer(26));
      }
    });
  });
*/
};

tcpconnect.start = function(router, options) {
  var self = this;
  for(var i=0; i<options.length; i++) {
    var opts = options[i];
    if(typeof opts == 'string') {
      opts = {host: '127.0.0.1', port: opts};
      var indexOfColon = opts.port.indexOf(':');
      if(indexOfColon >= 0) {
        opts = {
          host: opts.port.split(':')[0],
          port: opts.port.split(':')[1]
        };
      }

    }
    tcpconnect(router, opts);
  }
};

tcpconnect.stop = function(){};

module.exports = tcpconnect;
