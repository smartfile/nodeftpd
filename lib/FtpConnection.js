/* eslint-disable no-octal */

var net = require('net');
var util = require('util');
var events = require('events');
var path = require('path');
var fsModule = require('fs');
var StatMode = require('stat-mode');
var dateformat = require('dateformat');
var lock = require('lock').Lock();

var glob = require('./glob');
var starttls = require('./starttls');
var Constants = require('./Constants');

var pathEscape = require('./helpers/pathEscape');
var withCwd = require('./helpers/withCwd');
var stripOptions = require('./helpers/stripOptions');
var leftPad = require('./helpers/leftPad');

var EventEmitter = events.EventEmitter;

// Use LOG for brevity.
var LOG = Constants.LOG_LEVELS;
var DOES_NOT_REQUIRE_AUTH = Constants.DOES_NOT_REQUIRE_AUTH;

var REQUIRES_CONFIGURED_DATA = Constants.REQUIRES_CONFIGURED_DATA;

function FtpConnection(properties) {
  var self = this;

  EventEmitter.call(this);

  Object.keys(properties).forEach(function(key) {
    self[key] = properties[key];
  });

  self.socket.setTimeout(0);
  self.socket.setNoDelay();

  if (properties.secure) {
    this._secureChannel('implicit');
  }

  self.socket.on('end', endHandler);
  self.socket.on('error', self._onError.bind(self));
  self.socket.on('close', self._onClose.bind(self));
  self.socket.on('data', self._onData.bind(self));

  self._writeBanner();
  self._logIf(LOG.INFO, 'Accepted a new client connection');

  function endHandler() {
    self._logIf(LOG.DEBUG, 'Client connection ended');
  }
}

util.inherits(FtpConnection, EventEmitter);

FtpConnection.prototype._onError = function(e) {
  this._logIf(LOG.ERROR, 'Client connection error: ' + util.inspect(e));
  this._closeCommandConnection(true);
};

FtpConnection.prototype._writeBanner = function() {
  this.respond(this.banner || '220 FTP server (nodeftpd) ready');
};

// TODO: rename this to writeLine?
FtpConnection.prototype.respond = function(message, callback) {
  this._writeText(this.socket, message + '\r\n', callback);
};

FtpConnection.prototype._logIf = function(verbosity, message) {
  this.server._logIf(verbosity, message, this);
};

// We don't want to use setEncoding because it screws up TLS, but we
// also don't want to explicitly specify ASCII encoding for every call to 'write'
// with a string argument.
FtpConnection.prototype._writeText = function(socket, data, callback) {
  if (!socket || !socket.writable) {
    this._logIf(LOG.DEBUG, 'Attempted writing to a closed socket:\n>> ' + data.trim());
    return;
  }
  this._logIf(LOG.TRACE, '>> ' + data.trim());
  return socket.write(data, 'utf8', callback);
};

FtpConnection.prototype._closeDataConnections = function(destroy) {
  if (this.dataSocket) {
    this._closeSocket(this.dataSocket, destroy);
    this.dataSocket = null;
  }
  if (this.pasv) {
    this.pasv.close();
    this.pasv = null;
  }
  this.dataConfigured = false;
};

FtpConnection.prototype._closeCommandConnection = function(destroy) {
  if (this.socket) {
    this._closeSocket(this.socket, destroy);
    this.socket = null;
  }
};

FtpConnection.prototype._createPassiveServer = function() {
  var self = this;

  return net.createServer(function(socket) {
    // This is simply a connection listener.
    // TODO: Should we keep track of *all* connections, or enforce just one?
    self._logIf(LOG.INFO, 'Passive data event: connect on port ' + this.address().port);

    if (self.secure) {
      self._logIf(LOG.INFO, 'Upgrading passive connection to TLS');
      starttls.starttlsServer(socket, self.server.options.tlsOptions, function(err, secureSocket) {
        if (err) {
          self._logIf(LOG.ERROR, 'Error upgrading passive connection to TLS:' + util.inspect(err));
          self._closeSocket(socket, true);
          self.dataConfigured = false;
          return;
        }

        if (secureSocket.authorized || self.server.options.allowUnauthorizedTls) {
          self._logIf(LOG.INFO, 'Secure passive connection started');
          // TODO: Check for existing dataSocket.
          self._setupDataSocket(secureSocket);
          return;
        }

        self._logIf(LOG.INFO, 'Closing disallowed unauthorized secure passive connection (allowUnauthorizedTls is off)');
        self._closeSocket(socket, true);
        self.dataConfigured = false;
      });
    } else {
      // TODO: Check for existing dataSocket.
      self._setupDataSocket(socket);
    }
  });
};

FtpConnection.prototype._setupDataSocket = function(socket) {
  var self = this;

  function allOver(socket, ename) {
    var port = socket.address().port;
    return function(err) {
      if (err) {
        self._logIf(LOG.ERROR, 'Data event: ' + ename + ' due to error: ' + util.inspect(err) + ' on port ' + port);
      } else {
        self._logIf(LOG.DEBUG, 'Data event: ' + ename + ' on port ' + port);
      }
      self.dataSocket = null;
    };
  }

  // Responses are not guaranteed to have an 'end' event
  // (https://github.com/joyent/node/issues/728), but we want to set
  // dataSocket to null as soon as possible, so we handle both events.
  self.dataSocket = socket
    .on('close', allOver(socket, 'close'))
    .on('end', allOver(socket, 'end'))
    .on('error', function(err) {
      self._logIf(LOG.ERROR, 'Data connection error: ' + err);
      if (self.dataSocket) {
        self._closeSocket(self.dataSocket, true);
        self.dataSocket = null;
      }
      self.dataConfigured = false;
    });

  (self.pasv || socket).emit('ready', socket);
};

FtpConnection.prototype._whenDataReady = function(callback) {
  var self = this;

  var socket = self.dataSocket;
  if (socket) {
    self._logIf(LOG.DEBUG, 'Using existing ' + (self.pasv ? '' : 'non-') +  'passive connection');
    callback(socket);
    return;
  }

  self._logIf(LOG.DEBUG, 'Currently no data connection; setting up ' + (self.pasv ? '' : 'non-') + 'passive connection to client');

  (self.pasv ||  net.connect(self.dataPort, self.dataHost || self.socket.remoteAddress, function() {
    self._setupDataSocket(this);
  })).once('ready', callback);
};

FtpConnection.prototype._onClose = function(hadError) {
  // I feel like some of this might be redundant since we probably close some
  // of these sockets elsewhere, but it is fine to call _closeSocket more than
  // once.
  this._closeDataConnections(hadError);
  this._closeCommandConnection(hadError);
  // TODO: LOG.DEBUG?
  this._logIf(LOG.INFO, 'Client connection closed');
};

FtpConnection.prototype._onData = function(data) {
  var self = this;

  if (self.hasQuit) {
    return;
  }

  data = data.toString('utf-8').trim();
  self._logIf(LOG.TRACE, '<< ' + data);
  // Don't want to include passwords in logs.
  self._logIf(LOG.INFO, 'FTP command: ' +
    data.replace(/^PASS [\s\S]*$/i, 'PASS ***')
  );

  var command;
  var commandArg;
  var index = data.indexOf(' ');
  if (index !== -1) {
    var parts = data.split(' ');
    command = parts.shift().toUpperCase();
    commandArg = parts.join(' ').trim();
  } else {
    command = data.toUpperCase();
    commandArg = '';
  }

  if (commandArg.indexOf('\\r') !== -1 ||
      commandArg.indexOf('\\n') !== -1) {
    self.respond('501 Syntax error in parameters or arguments.');
    return;
  }

  lock('command', function(releaser) {
    // releaser is a factory function. It creates a callback that will unlock this critical section.
    var release = releaser();
    var m = '_command_' + command;
    if (!self[m]) {
      return self.respond('502 Command not implemented.', release);
    }

    function checkData() {
      if (REQUIRES_CONFIGURED_DATA[command] && !self.dataConfigured) {
        return self.respond('425 Data connection not configured; send PASV or PORT', release);
      }

      try {
        self[m](release, commandArg, command);
      }
      catch (e) {
        release();
        throw e;
      }
    }

    if (self.allowedCommands != null && self.allowedCommands[command] !== true) {
      self.respond('502 ' + command + ' not implemented.', release);
    } else if (DOES_NOT_REQUIRE_AUTH[command]) {
      try {
        self[m](release, commandArg, command);
      }
      catch (e) {
        release();
        throw e;
      }
    } else {
      // If 'tlsOnly' option is set, all commands which require user authentication will only
      // be permitted over a secure connection. See RFC4217 regarding error code.
      if (!self.secure && self.server.options.tlsOnly) {
        self.respond('522 Protection level not sufficient; send AUTH TLS', release);
      } else if (self.username) {
        checkData();
      } else {
        self.respond('530 Not logged in.', release);
      }
    }

    self.previousCommand = command;
  });
};

// Specify the user's account (superfluous)
FtpConnection.prototype._command_ACCT = function(release) {
  this.respond('202 Command not implemented, superfluous at this site.', release);
};

// Allocate storage space (superfluous)
FtpConnection.prototype._command_ALLO = function(release) {
  this.respond('202 Command not implemented, superfluous at this site.', release);
};

FtpConnection.prototype._command_AUTH = function(release, commandArg) {
  var self = this;

  if (!self.server.options.tlsOptions || commandArg !== 'TLS') {
    return self.respond('502 Command not implemented', release);
  }

  self.respond('234 Honored', function() {
    release();
    self._logIf(LOG.INFO, 'Establishing secure connection...');

    if (!self.socket.authorized && !self.server.options.allowUnauthorizedTls) {
      self._logIf(LOG.INFO, 'Closing unauthorized connection (allowUnauthorizedTls is off)');
      self._closeSocket(self.socket, true);
      return;
    }

    self._secureChannel('explicit');
    self.socket.on('data', function(data) {
      self._onData(data);
    });
  });
};

FtpConnection.prototype._secureChannel = function(type) {
  var self = this;

  starttls.starttlsServer(self.socket, self.server.options.tlsOptions, function(err, secureSocket) {
    if (err) {
      self._logIf(LOG.ERROR, 'Error upgrading connection to TLS: ' + util.inspect(err));
      self._closeSocket(self.socket, true);
      return;
    }

    self._logIf(LOG.INFO, `Secure connection started (${type})`);
    self.socket = secureSocket;
    self.secure = true;
    return;
  });
};

// Change working directory to parent directory
FtpConnection.prototype._command_CDUP = function(release) {
  var pathServer = path.dirname(this.cwd);
  var pathEscaped = pathEscape(pathServer);
  this.cwd = pathServer;
  this.respond('250 Directory changed to "' + pathEscaped + '"', release);
};

// Change working directory
FtpConnection.prototype._command_CWD = function(release, pathRequest) {
  var pathServer = withCwd(this.cwd, pathRequest);
  var pathFs = path.join(this.root, pathServer);
  var pathEscaped = pathEscape(pathServer);
  this.fs.stat(pathFs, function(err, stats) {
    if (err) {
      this._logIf(LOG.ERROR, 'CWD ' + pathRequest + ': ' + err);
      this.respond('550 Directory not found.', release);
    } else if (!stats.isDirectory()) {
      this._logIf(LOG.WARN, 'Attempt to CWD to non-directory');
      this.respond('550 Not a directory', release);
    } else {
      this.cwd = pathServer;
      this.respond('250 CWD successful. "' + pathEscaped + '" is current directory', release);
    }
  }.bind(this));
};

FtpConnection.prototype._command_DELE = function(release, commandArg) {
  var self = this;

  var filename = withCwd(self.cwd, commandArg);
  self.fs.unlink(path.join(self.root, filename), function(err) {
    if (err) {
      self._logIf(LOG.ERROR, 'Error deleting file: ' + filename + ', ' + err);
      // write error to socket
      self.respond('550 Permission denied', release);
    } else {
      self.respond('250 File deleted', release);
    }
  });
};

FtpConnection.prototype._command_FEAT = function(release) {
  // Get the feature list implemented by the server. (RFC 2389)
  this.respond(
    '211-Features\r\n' +
          ' SIZE\r\n' +
          ' UTF8\r\n' +
          ' MDTM\r\n' +
          (!this.server.options.tlsOptions ? '' :
            ' AUTH TLS\r\n' +
                  ' PBSZ\r\n' +
                  ' UTF8\r\n' +
                  ' PROT\r\n'
          ) +
          '211 end',
    release
  );
};

FtpConnection.prototype._command_OPTS = function(release, commandArg) {
  // http://tools.ietf.org/html/rfc2389#section-4
  if (commandArg.toUpperCase() === 'UTF8 ON') {
    this.respond('200 OK', release);
  } else {
    this.respond('451 Not supported', release);
  }
};

// Print the file modification time
FtpConnection.prototype._command_MDTM = function(release, file) {
  var self = this;
  file = withCwd(this.cwd, file);
  file = path.join(this.root, file);
  this.fs.stat(file, function(err, stats) {
    if (err) {
      self.respond('550 File unavailable', release);
    } else {
      self.respond('213 ' + dateformat(stats.mtime, 'yyyymmddhhMMss'), release);
    }
  });
};

FtpConnection.prototype._command_LIST = function(release, commandArg) {
  this._LIST(release, commandArg, true, 'LIST');
};

FtpConnection.prototype._command_NLST = function(release, commandArg) {
  this._LIST(release, commandArg, false, 'NLST');
};

FtpConnection.prototype._command_STAT = function(release, commandArg) {
  if (commandArg) {
    this._LIST(release, commandArg, true, 'STAT');
  } else {
    this.respond('211 FTP Server Status OK', release);
  }
};

FtpConnection.prototype._LIST = function(release, commandArg, detailed, cmd) {
  /*
   Normally the server responds with a mark using code 150. It then stops accepting new connections, attempts to send the contents of the directory over the data connection, and closes the data connection. Finally it

   accepts the LIST or NLST request with code 226 if the entire directory was successfully transmitted;
   rejects the LIST or NLST request with code 425 if no TCP connection was established;
   rejects the LIST or NLST request with code 426 if the TCP connection was established but then broken by the client or by network failure; or
   rejects the LIST or NLST request with code 451 if the server had trouble reading the directory from disk.

   The server may reject the LIST or NLST request (with code 450 or 550) without first responding with a mark. In this case the server does not touch the data connection.
   */

  var self = this;

  // LIST may be passed options (-a in particular). We just ignore any of these.
  // (In the particular case of -a, we show hidden files anyway.)
  var dirname = stripOptions(commandArg);
  var dir = withCwd(self.cwd, dirname);

  glob.setMaxStatsAtOnce(self.server.options.maxStatsAtOnce);
  glob.glob(path.join(self.root, dir), self.fs, function(err, files) {
    if (err) {
      self._logIf(LOG.ERROR, 'Error sending file list, reading directory: ' + err);
      self.respond('550 Not a directory', release);
      return;
    }

    if (self.server.options.hideDotFiles) {
      files = files.filter(function(file) {
        if (file.name && file.name[0] !== '.') {
          return true;
        }
      });
    }

    self._logIf(LOG.INFO, 'Directory has ' + files.length + ' files');
    if (files.length === 0) {
      return self._listFiles(release, [], detailed, cmd);
    }

    var fileInfos; // To contain list of files with info for each.

    if (!detailed) {
      // We're not doing a detailed listing, so we don't need to get username
      // and group name.
      fileInfos = files;
      return finish();
    }

    // Now we need to get username and group name for each file from user/group ids.
    fileInfos = [];

    var CONC = self.server.options.maxStatsAtOnce;
    var total = files.length;
    for (var i = 0; i < CONC; ++i) {
      handleFile();
    }

    function handleFile() {
      if (fileInfos.length === total) {
        return finish();
      }

      if (files.length === 0) {
        return;
      }

      var file = files.shift();
      self.server.getUsernameFromUid(file.stats.uid, function(e1, uname) {
        self.server.getGroupFromGid(file.stats.gid, function(e2, gname) {
          if (e1 || e2) {
            self._logIf(LOG.WARN, 'Error getting user/group name for file: ' + util.inspect(e1 || e2));
            uname = null;
            gname = null;
          }
          fileInfos.push({
            file: file,
            uname: uname,
            gname: gname,
          });
          handleFile();
        });
      });
    }

    function finish() {
      // Sort file names.
      if (!self.server.options.dontSortFilenames) {
        if (self.server.options.filenameSortMap !== false) {
          var sm = (
            self.server.options.filenameSortMap ||
            function(x) {
              return x.toUpperCase();
            }
          );
          for (var i = 0; i < fileInfos.length; ++i) {
            fileInfos[i]._s = sm(detailed ? fileInfos[i].file.name : fileInfos[i].name);
          }
        }

        var sf = (self.server.options.filenameSortFunc ||
            function(x, y) {
              return x.localeCompare(y);
            });
        fileInfos = fileInfos.sort(function(x, y) {
          if (self.server.options.filenameSortMap !== false) {
            return sf(x._s, y._s);
          } else if (detailed) {
            return sf(x.file.name, y.file.name);
          } else {
            return sf(x.name, y.name);
          }
        });
      }

      self._listFiles(release, fileInfos, detailed, cmd);
    }
  }, self.server.options.noWildcards);
};

FtpConnection.prototype._listFiles = function(release, fileInfos, detailed, cmd) {
  var self = this;

  var m = '150 Here comes the directory listing';
  var BEGIN_MSGS = {
    LIST: m, NLST: m, STAT: '213-Status follows',
  };
  m = '226 Transfer OK';
  var END_MSGS = {
    LIST: m, NLST: m, STAT: '213 End of status', ERROR: '550 Error listing files',
  };

  self.respond(BEGIN_MSGS[cmd], function() {
    release();
    if (cmd === 'STAT') {
      writeFileList(self.socket);
    } else {
      self._whenDataReady(writeFileList);
    }

    function writeFileList(socket) {
      if (fileInfos.length === 0) {
        return success();
      }

      function success(err) {
        self.respond(END_MSGS[err && 'ERROR' || cmd]);

        if (cmd !== 'STAT') {
          self._closeSocket(socket);
        }
      }

      self._logIf(LOG.DEBUG, 'Sending file list');

      for (var i = 0; i < fileInfos.length; ++i) {
        var fileInfo = fileInfos[i];

        var line = '';
        var file;

        if (!detailed) {
          file = fileInfo;
        } else {
          file = fileInfo.file;
          var s = file.stats;
          var allModes = (new StatMode({mode: s.mode})).toString();
          var rwxModes = allModes.substr(1, 9);
          line += (s.isDirectory() ? 'd' : '-') + rwxModes;
          // ^-- Clients don't need to know about special files and pipes
          line += ' 1 ' +
            (fileInfo.uname || 'ftp') + ' ' +
            (fileInfo.gname === null ? 'ftp' : fileInfo.gname) + ' ';
          line += leftPad(s.size.toString(), 12) + ' ';
          var d = new Date(s.mtime);
          line += leftPad(dateformat(d, 'mmm dd HH:MM'), 12) + ' ';
        }
        line += file.name + '\r\n';
        self._writeText(
          socket,
          line,
          (i === fileInfos.length - 1 ? success : undefined)
        );
      }
    }
  });
};

// Create a directory
FtpConnection.prototype._command_MKD = function(release, pathRequest) {
  var pathServer = withCwd(this.cwd, pathRequest);
  var pathEscaped = pathEscape(pathServer);
  var pathFs = path.join(this.root, pathServer);
  this.fs.mkdir(pathFs, 0755, function(err) {
    if (err) {
      this._logIf(LOG.ERROR, 'MKD ' + pathRequest + ': ' + err);
      this.respond('550 "' + pathEscaped + '" directory NOT created', release);
    } else {
      this.respond('257 "' + pathEscaped + '" directory created', release);
    }
  }.bind(this));
};

// Perform a no-op (used to keep-alive connection)
FtpConnection.prototype._command_NOOP = function(release) {
  this.respond('200 OK', release);
};

FtpConnection.prototype._command_PORT = function(release, x, y) {
  this._PORT(release, x, y);
};

FtpConnection.prototype._command_EPRT = function(release, x, y) {
  this._PORT(release, x, y);
};

FtpConnection.prototype._PORT = function(release, commandArg, command) {
  var self = this;
  var m;
  var host;
  var port;

  // TODO: should the arg be false here?
  self._closeDataConnections(true);

  if (command === 'PORT') {
    m = commandArg.match(/^([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3}),([0-9]{1,3})$/);
    if (!m) {
      return self.respond('501 Bad argument to PORT', release);
    }

    host = m[1] + '.' + m[2] + '.' + m[3] + '.' + m[4];
    port = (parseInt(m[5], 10) << 8) + parseInt(m[6], 10);
    if (isNaN(port)) {
      // The value should never be NaN because the relevant groups in the regex matche 1-3 digits.
      throw new Error('Impossible NaN in FtpConnection.prototype._PORT');
    }
  } else { // EPRT
    if (commandArg.length >= 3 && commandArg.charAt(0) === '|' &&
        commandArg.charAt(2) === '|' && commandArg.charAt(1) === '2') {
      // Only IPv4 is supported.
      return self.respond('522 Server cannot handle IPv6 EPRT commands, use (1)', release);
    }

    m = commandArg.match(/^\|1\|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\|([0-9]{1,5})/);
    if (!m) {
      return self.respond('501 Bad Argument to EPRT', release);
    }

    var r = parseInt(m[2], 10);
    if (isNaN(r)) {
      // The value should never be NaN because the relevant group in the regex matches 1-5 digits.
      throw new Error('Impossible NaN in FtpConnection.prototype._PORT (2)');
    }

    host = m[1];
    port = r;
  }

  if (port > 65535 || port < 1024) {
    return self.respond('501 Bad argument to ' + command + ' (invalid port number)', release);
  }

  self.dataConfigured = true;
  self.dataHost = host;
  self.dataPort = port;
  self._logIf(LOG.DEBUG, 'self.dataHost, self.dataPort set to ' + self.dataHost + ':' + self.dataPort);
  self.respond('200 OK', release);
};

FtpConnection.prototype._command_PASV = function(release, x, y) {
  this._PASV(release, x, y);
};

FtpConnection.prototype._command_EPSV = function(release, x, y) {
  this._PASV(release, x, y);
};

FtpConnection.prototype._PASV = function(release, commandArg, command) {
  var self = this;

  self.dataConfigured = false;

  if (command === 'EPSV' && commandArg && commandArg !== '1') {
    return self.respond('202 Not supported', release);
  }

  // not sure whether the spec limits to 1 data connection at a time ...
  if (self.dataSocket) {
    self._closeSocket(self.dataSocket, true);
    self.dataSocket = null;
  }

  self._setupPASV(release, commandArg, command);
};

FtpConnection.prototype._writePASVReady = function(release, command) {
  var self = this;

  self.dataConfigured = true;

  self._logIf(LOG.DEBUG, 'Telling client that it can connect now');

  var host = self.server.host;
  var port = self.pasv.address().port;
  if (command === 'PASV') {
    var i1 = (port / 256) | 0;
    var i2 = port % 256;
    self.respond('227 Entering Passive Mode (' + host.split('.').join(',') + ',' + i1 + ',' + i2 + ')', release);
  } else { // EPASV
    self.respond('229 Entering Extended Passive Mode (|||' + port + '|)', release);
  }
};

// Keep trying ports in the range supplied until either:
//     (i)   It works
//     (ii)  We get an error that's not just EADDRINUSE
//     (iii) We run out of ports to try.
FtpConnection.prototype._setupPASV = function(release, commandArg, command) {
  var self = this;

  if (self.pasv) {
    self._writePASVReady(release, command);
    return;
  }

  self._logIf(LOG.DEBUG, 'Setting up listener for passive connections');

  var firstPort = this.server.options.pasvPortRangeStart;
  var lastPort = this.server.options.pasvPortRangeEnd;

  this._createPassiveServer()
    .on('error', function(e) {
      if (self.pasv === null && e.code === 'EADDRINUSE' && e.port < (lastPort || firstPort || 0)) {
        this.listen(++e.port);
        return;
      }

      self._logIf(LOG.WARN, 'Passive Error with passive data listener: ' + util.inspect(e));
      self.respond('421 Server was unable to open passive connection listener', release);
      self.dataConfigured = false;
      self.dataSocket = null;
      self.pasv = null;
    })

    // Once we're successfully listening, tell the client
    .on('listening', function() {
      self._logIf(LOG.DEBUG, 'Passive data connection listening on port ' + this.address().port);
      self.pasv = this;
      self._writePASVReady(release, command);
    })

    .on('close', function() {
      self.pasv = null;
      self._logIf(LOG.DEBUG, 'Passive data listener closed');
    })

    .listen(firstPort || lastPort || 0);
};

FtpConnection.prototype._command_PBSZ = function(release, commandArg) {
  if (this.secure) {
    this.pbszReceived = true;
  }

  this.respond(
    !this.server.options.tlsOptions ? '202 Not supported' :
      !this.secure ? '503 Secure connection not established' /* Protection Buffer Size (RFC 2228) */ :
        parseInt(commandArg, 10) !== 0 ? '200 buffer too big, PBSZ=0' :
        // RFC 2228 specifies that a 200 reply must be sent specifying a more
        // satisfactory PBSZ size (0 in our case, since we're using TLS).
        // Doubt that this will do any good if the client was already confused
        // enough to send a non-zero value, but ok...
          '200 OK',
    release
  );
};

FtpConnection.prototype._command_PROT = function(release, commandArg) {
  this.respond(
    !this.server.options.tlsOptions ? '202 Not supported' :
      !this.pbszReceived ? '503 No PBSZ command received' :
        (commandArg === 'S' || commandArg === 'E' || commandArg === 'C') ? '536 Not supported' :
          commandArg !== 'P' ? '504 Not recognized' /* Don't even recognize this one... */ :
            '200 OK',
    release
  );
};

// Print the current working directory.
FtpConnection.prototype._command_PWD = function(release, commandArg) {
  this.respond(
    commandArg === ''
      ? '257 "' + pathEscape(this.cwd) + '" is current directory'
      : '501 Syntax error in parameters or arguments.',
    release
  );
};

FtpConnection.prototype._command_QUIT = function(release) {
  var self = this;

  self.hasQuit = true;
  self.respond('221 Goodbye', function(err) {
    release();
    if (err) {
      self._logIf(LOG.ERROR, "Error writing 'Goodbye' message following QUIT");
    }
    // TODO: should the arg be false here?
    self._onClose(true);
  });
};

FtpConnection.prototype._command_RETR = function(release, commandArg) {
  var filename = path.join(this.root, withCwd(this.cwd, commandArg));

  if (this.server.options.useReadFile) {
    this._RETR_usingReadFile(release, commandArg, filename);
  } else {
    this._RETR_usingCreateReadStream(release, commandArg, filename);
  }
};

FtpConnection.prototype._RETR_usingCreateReadStream = function(release, commandArg, filename) {
  var self = this;
  var startTime = new Date();

  self.emit('file:retr', 'open', {
    user: self.username,
    file: filename,
    sTime: startTime,
  });

  function afterOk(callback) {
    self.respond('150 Opening ' + self.mode.toUpperCase() + ' mode data connection', callback);
  }

  self.fs.open(filename, 'r', function(err, fd) {
    if (err) {
      self.emit('file:retr', 'error', {
        user: self.username,
        file: filename,
        filesize: 0,
        sTime: startTime,
        eTime: new Date(),
        duration: new Date() - startTime,
        errorState: true,
        error: err,
      });
      if (err.code === 'ENOENT') {
        self.respond('550 Not Found', release);
      } else { // Who knows what's going on here...
        self.respond('550 Not Accessible', release);
        self._logIf(LOG.ERROR, "Error at read of '" + filename + "' other than ENOENT " + err);
      }
    } else {
      afterOk(function() {
        release();
        self._whenDataReady(function(socket) {
          var readLength = 0;
          var now = new Date();
          var rs = self.fs.createReadStream(null, {fd: fd});
          rs.pause();
          rs.once('error', function(err) {
            self.emit('file:retr', 'close', {
              user: self.username,
              file: filename,
              /** @deprecated filesize is deprecated, use bytesRead/bytesWritten instead */
              filesize: 0,
              bytesRead: rs.bytesRead,
              sTime: startTime,
              eTime: now,
              duration: now - startTime,
              errorState: true,
              error: err,
            });
          });

          rs.on('data', function(buffer) {
            readLength += buffer.length;
          });

          rs.on('end', function() {
            var now = new Date();
            self.emit('file:retr', 'close', {
              user: self.username,
              file: filename,
              /** @deprecated filesize is deprecated, use bytesRead/bytesWritten instead */
              filesize: 0,
              bytesRead: rs.bytesRead,
              sTime: startTime,
              eTime: now,
              duration: now - startTime,
              errorState: false,
            });
            self.respond('226 Closing data connection, sent ' + readLength + ' bytes');
          });

          rs.pipe(socket);
          rs.resume();
        });
      });
    }
  });
};

FtpConnection.prototype._RETR_usingReadFile = function(release, commandArg, filename) {
  var self = this;
  var startTime = new Date();

  self.emit('file:retr', 'open', {
    user: self.username,
    file: filename,
    sTime: startTime,
  });

  function afterOk(callback) {
    self.respond('150 Opening ' + self.mode.toUpperCase() + ' mode data connection', callback);
  }

  self.fs.readFile(filename, function(err, contents) {
    if (err) {
      self.emit('file:retr', 'error', {
        user: self.username,
        file: filename,
        /** @deprecated filesize is deprecated, use bytesRead/bytesWritten instead */
        filesize: 0,
        bytesRead: 0,
        sTime: startTime,
        eTime: new Date(),
        duration: new Date() - startTime,
        errorState: true,
        error: err,
      });
      if (err.code === 'ENOENT') {
        self.respond('550 Not Found', release);
      } else { // Who knows what's going on here...
        self.respond('550 Not Accessible', release);
        self._logIf(LOG.ERROR, "Error at read of '" + filename + "' other than ENOENT " + err);
      }
    } else {
      afterOk(function() {
        release();
        self._whenDataReady(function(socket) {
          self.emit('file:retr:contents', {filename: filename, data: contents});
          socket.write(contents);
          var contentLength = contents.length;
          self.respond('226 Closing data connection, sent ' + contentLength + ' bytes');
          self.emit('file:retr', 'close', {
            user: self.username,
            file: filename,
            /** @deprecated filesize is deprecated, use bytesRead/bytesWritten instead */
            filesize: contentLength,
            bytesRead: contentLength,
            sTime: startTime,
            eTime: new Date(),
            duration: new Date() - startTime,
            errorState: false,
          });
          if (self.dataSocket) {
            self._closeSocket(self.dataSocket);
            self.dataSocket = null;
          }
        });
      });
    }
  });
};

// Remove a directory
FtpConnection.prototype._command_RMD = function(release, pathRequest) {
  var pathServer = withCwd(this.cwd, pathRequest);
  var pathFs = path.join(this.root, pathServer);
  this.fs.rmdir(pathFs, function(err) {
    if (err) {
      this._logIf(LOG.ERROR, 'RMD ' + pathRequest + ': ' + err);
      this.respond('550 Delete operation failed', release);
    } else {
      this.respond('250 "' + pathServer + '" directory removed', release);
    }
  }.bind(this));
};

FtpConnection.prototype._command_RNFR = function(release, commandArg) {
  var self = this;
  self.filefrom = withCwd(self.cwd, commandArg);
  self._logIf(LOG.DEBUG, 'Rename from ' + self.filefrom);
  self.respond('350 Ready for destination name', release);
};

FtpConnection.prototype._command_RNTO = function(release, commandArg) {
  var self = this;
  var fileto = withCwd(self.cwd, commandArg);
  self.fs.rename(path.join(self.root, self.filefrom), path.join(self.root, fileto), function(err) {
    if (err) {
      self._logIf(LOG.ERROR, 'Error renaming file from ' + self.filefrom + ' to ' + fileto);
      self.respond('550 Rename failed' + (err.code === 'ENOENT' ? '; file does not exist' : '', release));
    } else {
      self.respond('250 File renamed successfully', release);
    }
  });
};

FtpConnection.prototype._command_SIZE = function(release, commandArg) {
  var self = this;

  var filename = withCwd(self.cwd, commandArg);
  self.fs.stat(path.join(self.root, filename), function(err, s) {
    if (err) {
      self._logIf(LOG.ERROR, "Error getting size of file '" + filename + "' ");
      self.respond('450 Failed to get size of file', release);
      return;
    }
    self.respond('213 ' + s.size + '', release);
  });
};

FtpConnection.prototype._command_TYPE = function(release, commandArg) {
  this.respond(
    commandArg === 'I' || commandArg === 'A'
      ? '200 OK'
      : '202 Not supported',
    release
  );
};

FtpConnection.prototype._command_SYST = function(release) {
  this.respond('215 UNIX Type: I', release);
};

FtpConnection.prototype._command_STOR = function(release, commandArg) {
  var filename = withCwd(this.cwd, commandArg);

  if (this.server.options.useWriteFile) {
    this._STOR_usingWriteFile(release, filename, 'w');
  } else {
    this._STOR_usingCreateWriteStream(release, filename, null, 'w');
  }
};

// 'initialBuffers' argument is set when this is called from _STOR_usingWriteFile.
FtpConnection.prototype._STOR_usingCreateWriteStream = function(release, filename, initialBuffers, flag) {
  var self = this;

  var wStreamFlags = {flags: flag || 'w', mode: 0644};
  var storeStream = self.fs.createWriteStream(path.join(self.root, filename), wStreamFlags);
  var notErr = true;
  // Adding for event metadata for file upload (STOR)
  var startTime = new Date();

  if (initialBuffers) {
    //todo: handle back-pressure
    initialBuffers.forEach(function(b) {
      storeStream.write(b);
    });
  }

  self._whenDataReady(function(socket) {
    socket.on('error', function(err) {
      notErr = false;
      self._logIf(LOG.ERROR, 'Data connection error: ' + util.inspect(err));
    });
    socket.pipe(storeStream);
  });

  storeStream.on('open', function() {
    self._logIf(LOG.DEBUG, 'File opened/created: ' + filename);
    self._logIf(LOG.DEBUG, 'Told client ok to send file data');
    // Adding event emitter for upload start time
    self.emit('file:stor', 'open', {
      user: self.username,
      file: filename,
      time: startTime,
    });

    self.respond('150 Ok to send data', release);
  });

  storeStream.on('error', function() {
    self.emit('file:stor', 'error', {
      user: self.username,
      file: filename,
      /** @deprecated filesize is deprecated, use bytesRead/bytesWritten instead */
      filesize: 0,
      bytesWritten: storeStream.bytesWritten,
      sTime: startTime,
      eTime: new Date(),
      duration: new Date() - startTime,
      errorState: !notErr,
    });
    storeStream.end();
    notErr = false;
    if (self.dataSocket) {
      self._closeSocket(self.dataSocket, true);
      self.dataSocket = null;
    }
    self.respond('426 Connection closed; transfer aborted');
  });

  storeStream.on('finish', function() {
    // Adding event emitter for completed upload.
    self.emit('file:stor', 'close', {
      user: self.username,
      file: filename,
      /** @deprecated filesize is deprecated, use bytesRead/bytesWritten instead */
      filesize: 0,
      bytesWritten: storeStream.bytesWritten,
      sTime: startTime,
      eTime: new Date(),
      duration: new Date() - startTime,
      errorState: !notErr,
    });
    notErr ? self.respond('226 Closing data connection') : true;
    if (self.dataSocket) {
      self._closeSocket(self.dataSocket);
      self.dataSocket = null;
    }
  });

};

FtpConnection.prototype._STOR_usingWriteFile = function(release, filename, flag) {
  var self = this;

  var erroredOut = false;
  var slurpBuf = new Buffer(1024);
  var totalBytes = 0;
  var startTime = new Date();

  self.emit('file:stor', 'open', {
    user: self.username,
    file: filename,
    time: startTime,
  });

  self.respond('150 Ok to send data', function() {
    release();
    self._whenDataReady(function(socket) {
      socket.on('data', dataHandler);
      socket.once('close', closeHandler);
      socket.once('error', errorHandler);
    });
  });


  function dataHandler(buf) {
    if (self.server.options.uploadMaxSlurpSize != null &&
        totalBytes + buf.length > self.server.options.uploadMaxSlurpSize) {
      // Give up trying to slurp it -- it's too big.

      // If the 'fs' module we've been given doesn't implement 'createWriteStream', then
      // we give up and send the client an error.
      if (!self.fs.createWriteStream) {
        if (self.dataSocket) {
          self._closeSocket(self.dataSocket, true);
          self.dataSocket = null;
        }
        self.respond('552 Requested file action aborted; file too big');
        return;
      }

      // Otherwise, we call _STOR_usingWriteStream, and tell it to prepend the stuff
      // that we've buffered so far to the file.
      self._logIf(LOG.WARN, 'uploadMaxSlurpSize exceeded; falling back to createWriteStream');
      self._STOR_usingCreateWriteStream(release, filename, [slurpBuf.slice(0, totalBytes), buf]);
      self.dataSocket.removeListener('data', dataHandler);
      self.dataSocket.removeListener('error', errorHandler);
      self.dataSocket.removeListener('close', closeHandler);
    } else {
      if (totalBytes + buf.length > slurpBuf.length) {
        var newLength = slurpBuf.length * 2;
        if (newLength < totalBytes + buf.length) {
          newLength = totalBytes + buf.length;
        }

        var newSlurpBuf = new Buffer(newLength);
        slurpBuf.copy(newSlurpBuf, 0, 0, totalBytes);
        slurpBuf = newSlurpBuf;
      }
      buf.copy(slurpBuf, totalBytes, 0, buf.length);
      totalBytes += buf.length;
    }
  }

  function closeHandler() {
    if (erroredOut) {
      return;
    }

    var wOptions = {flag: flag || 'w', mode: 0644};
    var contents = {filename: filename, data: slurpBuf.slice(0, totalBytes)};
    self.emit('file:stor:contents', contents);
    self.fs.writeFile(path.join(self.root, filename), contents.data, wOptions, function(err) {
      self.emit('file:stor', 'close', {
        user: self.username,
        file: filename,
        /** @deprecated filesize is deprecated, use bytesRead/bytesWritten instead */
        filesize: totalBytes,
        bytesWritten: totalBytes,
        sTime: startTime,
        eTime: new Date(),
        duration: new Date() - startTime,
        errorState: err ? true : false,
      });
      if (err) {
        erroredOut = true;
        self._logIf(LOG.ERROR, 'Error writing file. ' + err);
        if (self.dataSocket) {
          self._closeSocket(self.dataSocket, true);
        }
        self.respond('426 Connection closed; transfer aborted');
        return;
      }

      self.respond('226 Closing data connection');
      if (self.dataSocket) {
        self._closeSocket(self.dataSocket);
      }
    });
  }

  function errorHandler() {
    erroredOut = true; // TODO RWO: should we not log the error and emit error and close the connection?
  }
};

FtpConnection.prototype._command_APPE = function(release, commandArg) {
  var filename = withCwd(this.cwd, commandArg);

  if (this.server.options.useWriteFile) {
    this._STOR_usingWriteFile(release, filename, 'a');
  } else {
    this._STOR_usingCreateWriteStream(release, filename, null, 'a');
  }
};

// Specify a username for login
FtpConnection.prototype._command_USER = function(release, username) {
  var self = this;

  if (self.server.options.tlsOnly && !self.secure) {
    self.respond(
      '530 This server does not permit login over ' +
      'a non-secure connection; ' +
      'connect using FTP-SSL with explicit AUTH TLS',
      release);
  } else {
    self.emit('command:user', username,
      function success() {
        self.respond('331 User name okay, need password.', release);
      },
      function failure() {
        self.respond('530 Not logged in.', release);
      }
    );
  }
};

// Specify a password for login
FtpConnection.prototype._command_PASS = function(release, password) {
  var self = this;

  if (self.previousCommand !== 'USER') {
    self.respond('503 Bad sequence of commands.', release);
  } else {
    self.emit('command:pass', password,
      function success(username, userFsModule) {
        function panic(error, method) {
          self._logIf(LOG.ERROR, method + ' signaled error ' + util.inspect(error));
          self.respond('421 Service not available, closing control connection.', function() {
            release();
            self._closeSocket(self.socket, true);
          });
        }
        function setCwd(cwd) {
          function setRoot(root) {
            self.root = root;
            self.respond('230 User logged in, proceed.', release);
          }

          self.cwd = cwd;
          if (self.server.getRoot.length <= 1) {
            setRoot(self.server.getRoot(self));
          } else {
            self.server.getRoot(self, function(err, root) {
              if (err) {
                panic(err, 'getRoot');
              } else {
                setRoot(root);
              }
            });
          }
        }
        self.username = username;
        self.fs = userFsModule || fsModule;
        if (self.server.getInitialCwd.length <= 1) {
          setCwd(withCwd(self.server.getInitialCwd(self)));
        } else {
          self.server.getInitialCwd(self, function(err, cwd) {
            if (err) {
              panic(err, 'getInitialCwd');
            } else {
              setCwd(withCwd(cwd));
            }
          });
        }
      },
      function failure() {
        self.respond('530 Not logged in.', release);
        self.username = null;
      }
    );
  }
};

FtpConnection.prototype._closeSocket = function(socket, shouldDestroy) {
  // TODO: Should we always use destroy() to avoid keeping sockets open longer
  // than necessary (and possibly exceeding OS max open sockets)?
  if (shouldDestroy || this.server.options.destroySockets) {
    // Don't call destroy() more than once.
    if (!socket.destroyed) {
      this._logIf(LOG.DEBUG, 'Closing socket on port ' + socket.address().port);
      socket.destroy();
    }
  } else {
    // Don't call `end()` more than once.
    if (socket.writable) {
      socket.end();
    }
  }
};

module.exports = FtpConnection;
