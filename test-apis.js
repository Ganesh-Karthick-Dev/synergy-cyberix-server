const axios = require('axios');

const BASE_URL = 'http://localhost:9000';

async function testAPIs() {
  console.log('🧪 Testing Cyberix Security Scanner APIs...\n');

  const tests = [
    {
      name: 'Health Check',
      method: 'GET',
      url: '/health',
      expectedStatus: 200
    },
    {
      name: 'API Info',
      method: 'GET', 
      url: '/api',
      expectedStatus: 200
    },
    {
      name: 'Get All Users',
      method: 'GET',
      url: '/api/users',
      expectedStatus: 200
    },
    {
      name: 'Get User Stats',
      method: 'GET',
      url: '/api/users/stats/overview',
      expectedStatus: 200
    },
    {
      name: 'Get Security Tools',
      method: 'GET',
      url: '/api/security-tools',
      expectedStatus: 200
    },
    {
      name: 'Get Tool Categories',
      method: 'GET',
      url: '/api/security-tools/categories',
      expectedStatus: 200
    },
    {
      name: 'Get Service Plans',
      method: 'GET',
      url: '/api/plans',
      expectedStatus: 200
    },
    {
      name: 'Get Ads',
      method: 'GET',
      url: '/api/ads',
      expectedStatus: 200
    },
    {
      name: 'Get Ad Stats',
      method: 'GET',
      url: '/api/ads/stats',
      expectedStatus: 200
    },
    {
      name: 'Get Notifications',
      method: 'GET',
      url: '/api/notifications',
      expectedStatus: 200
    },
    {
      name: 'Get Notification Stats',
      method: 'GET',
      url: '/api/notifications/stats',
      expectedStatus: 200
    },
    {
      name: 'Get Dashboard Stats',
      method: 'GET',
      url: '/api/dashboard/stats',
      expectedStatus: 200
    },
    {
      name: 'Get Recent Activity',
      method: 'GET',
      url: '/api/dashboard/activity',
      expectedStatus: 200
    },
    {
      name: 'Get Revenue Chart',
      method: 'GET',
      url: '/api/dashboard/revenue-chart',
      expectedStatus: 200
    },
    {
      name: 'Get Users Chart',
      method: 'GET',
      url: '/api/dashboard/users-chart',
      expectedStatus: 200
    }
  ];

  let passed = 0;
  let failed = 0;

  for (const test of tests) {
    try {
      console.log(`Testing ${test.name}...`);
      const response = await axios({
        method: test.method,
        url: `${BASE_URL}${test.url}`,
        timeout: 5000
      });

      if (response.status === test.expectedStatus) {
        console.log(`✅ ${test.name} - PASSED (${response.status})`);
        passed++;
      } else {
        console.log(`❌ ${test.name} - FAILED (Expected: ${test.expectedStatus}, Got: ${response.status})`);
        failed++;
      }
    } catch (error) {
      console.log(`❌ ${test.name} - ERROR: ${error.message}`);
      failed++;
    }
  }

  console.log(`\n📊 Test Results:`);
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📈 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);

  if (failed === 0) {
    console.log('\n🎉 All APIs are working correctly!');
  } else {
    console.log('\n⚠️  Some APIs need attention.');
  }
}

// Test user registration
async function testRegistration() {
  console.log('\n🧪 Testing User Registration...\n');
  
  try {
    const response = await axios.post(`${BASE_URL}/api/register`, {
      firstName: 'Test',
      lastName: 'User',
      email: 'test@example.com',
      phone: '+1-555-123-4567',
      subscriptionType: 'FREE'
    });

    console.log('✅ User Registration - PASSED');
    console.log('Response:', JSON.stringify(response.data, null, 2));
  } catch (error) {
    console.log('❌ User Registration - ERROR:', error.response?.data || error.message);
  }
}

// Run tests
async function runTests() {
  await testAPIs();
  await testRegistration();
}

runTests().catch(console.error);


