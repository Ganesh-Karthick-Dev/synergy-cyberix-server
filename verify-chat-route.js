// Quick verification script to test if chat route is registered
const http = require('http');

const testChatRoute = () => {
  const options = {
    hostname: 'localhost',
    port: 4005, // Change if your backend runs on different port
    path: '/api/chat',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  };

  const req = http.request(options, (res) => {
    console.log(`Status Code: ${res.statusCode}`);
    
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      console.log('Response:', data);
      if (res.statusCode === 404) {
        console.log('\n❌ Route not found! Backend server needs to be restarted.');
      } else if (res.statusCode === 400) {
        console.log('\n✅ Route is registered! (400 is expected for missing message)');
      } else {
        console.log('\n✅ Route is accessible!');
      }
    });
  });

  req.on('error', (error) => {
    console.error('❌ Error:', error.message);
    console.log('\n⚠️  Make sure the backend server is running on port 4005');
  });

  // Send empty body to test route existence (will get 400, but route exists)
  req.write(JSON.stringify({}));
  req.end();
};

console.log('Testing chat route...\n');
testChatRoute();

