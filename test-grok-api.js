// Quick test script to verify Grok API configuration
require('dotenv').config();
const axios = require('axios');

const GROK_API_KEY = process.env.GROK_API_KEY || process.env.VITE_GROK_API_KEY;
const GROK_API_URL = process.env.GROK_API_URL || 'https://api.x.ai/v1/chat/completions';
const GROK_MODEL = process.env.GROK_MODEL || 'grok-3'; // grok-beta was deprecated

console.log('\n=== Testing Grok API Configuration ===\n');
console.log('API URL:', GROK_API_URL);
console.log('Model:', GROK_MODEL);
console.log('API Key:', GROK_API_KEY ? `${GROK_API_KEY.substring(0, 10)}...` : 'NOT SET');
console.log('\n');

if (!GROK_API_KEY) {
  console.error('❌ ERROR: GROK_API_KEY is not set in .env file');
  process.exit(1);
}

// Test with a simple message
const testMessage = {
  model: GROK_MODEL,
  messages: [
    {
      role: 'user',
      content: 'Hello, say hi if you can hear me'
    }
  ],
  temperature: 0.7,
  max_tokens: 100
};

console.log('Sending test request...\n');

axios.post(GROK_API_URL, testMessage, {
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${GROK_API_KEY}`
  },
  timeout: 30000
})
.then(response => {
  console.log('✅ SUCCESS! Grok API is working!\n');
  console.log('Response:', JSON.stringify(response.data, null, 2));
})
.catch(error => {
  console.error('❌ ERROR: Grok API request failed\n');
  
  if (error.response) {
    console.error('Status:', error.response.status);
    console.error('Status Text:', error.response.statusText);
    console.error('Error Data:', JSON.stringify(error.response.data, null, 2));
    console.error('\nPossible issues:');
    if (error.response.status === 404) {
      console.error('- 404: Wrong API endpoint URL or model name');
      console.error('  Try different model names: grok, grok-2, grok-beta-2');
      console.error('  Or check if you need a different API endpoint');
    } else if (error.response.status === 401) {
      console.error('- 401: Invalid API key');
      console.error('  Check your GROK_API_KEY in .env file');
    }
  } else if (error.request) {
    console.error('No response received:', error.message);
  } else {
    console.error('Error:', error.message);
  }
  
  process.exit(1);
});

