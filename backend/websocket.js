const WebSocket = require('ws');

function initializeWebSocket(port) {
  const wss = new WebSocket.Server({ port });

  console.log(`Zabbix SOC WebSocket running on ws://localhost:${port}`);

  wss.on('connection', (ws) => {
    console.log('Frontend connected to the WebSocket server.');

    // Send a welcome message
    ws.send(JSON.stringify({ 
      type: 'status', 
      message: 'WebSocket Connected', 
      timestamp: new Date().toISOString() 
    }));

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
      console.log('Received message from frontend:', message.toString());
      // we can echo or perform logic here in the future
    });

    // Cleanup when the connection is closed
    ws.on('close', () => {
      console.log('Frontend disconnected from WebSocket server.');
      clearInterval(pingInterval);
    });
  });
}

module.exports = initializeWebSocket;
