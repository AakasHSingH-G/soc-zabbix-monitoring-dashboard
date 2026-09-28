const WebSocket = require('ws');

function getSessionToken(request) {
  const cookies = request.headers.cookie || '';
  const match = cookies.split(';').map(value => value.trim()).find(value => value.startsWith('soc_session='));
  return match ? decodeURIComponent(match.slice('soc_session='.length)) : '';
}

function initializeWebSocket(server, sessions) {
  const wss = new WebSocket.Server({ noServer: true });

  server.on('upgrade', (request, socket, head) => {
    if (request.url !== '/ws') {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }

    const origin = request.headers.origin;
    const requestHost = request.headers.host;
    const sameOrigin = !origin || origin === `http://${requestHost}` || origin === `https://${requestHost}`;
    if (!sameOrigin) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    const session = sessions.get(getSessionToken(request));
    if (!session || session.expiresAt <= Date.now()) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  });

  const address = server.address && typeof server.address === 'function' ? server.address() : null;
  const logUrl = address && address.port ? `ws://localhost:${address.port}/ws` : 'WebSocket attached to HTTP server';
  console.log(`Zabbix SOC WebSocket running on ${logUrl}`);

  // Global broadcast function — webhook /api/webhook/new-device use karta hai
  global.wsBroadcast = (message) => {
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  };

  wss.on('connection', (ws) => {
    console.log('Frontend connected to the WebSocket server.');

    // Send a welcome message if the socket is open
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ 
        type: 'status', 
        message: 'WebSocket Connected', 
        timestamp: new Date().toISOString() 
      }));
    }

    // Start sending simulated health pings every 5 seconds
    const pingInterval = setInterval(() => {
      const pingData = {
        type: 'ping',
        message: 'System Health Check',
        uptime: process.uptime(),
        memory: process.memoryUsage().rss / 1024 / 1024, // in MB
        timestamp: new Date().toISOString()
      };
      
      // Ensure the socket is still open before sending
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(pingData));
      }
    }, 5000);

    // Listen for incoming messages from the frontend
    ws.on('message', (message) => {
      if (message.length > 64 * 1024) {
        ws.close(1009, 'Message too large');
        return;
      }
      try {
        const payload = JSON.parse(message.toString());
        if (payload.type !== 'NEW_DEVICE' || !payload.data || typeof payload.data !== 'object') return;
      } catch {
        ws.close(1003, 'Invalid JSON');
      }
    });

    // Cleanup when the connection is closed
    ws.on('close', () => {
      console.log('Frontend disconnected from WebSocket server.');
      clearInterval(pingInterval);
    });
  });
}

module.exports = initializeWebSocket;

