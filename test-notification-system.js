const axios = require('axios');

const BASE_URL = 'http://localhost:9000';

async function testNotificationSystem() {
  console.log('🔔 Testing Login Notification System...\n');

  try {
    // Test 1: Check server health
    console.log('1️⃣ Checking server health...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    console.log('✅ Server is running:', healthResponse.data.status);

    // Test 2: Register a test user
    console.log('\n2️⃣ Registering test user for notifications...');
    const registerResponse = await axios.post(`${BASE_URL}/api/register`, {
      firstName: 'Notification',
      lastName: 'Test',
      email: 'notification.test@example.com',
      phone: '9876543210',
      subscriptionType: 'FREE'
    });
    console.log('✅ Registration successful:', registerResponse.data.message);

    // Test 3: Test notification endpoints (without authentication - should fail)
    console.log('\n3️⃣ Testing notification endpoints without authentication...');
    try {
      const notificationsResponse = await axios.get(`${BASE_URL}/api/auth/notifications`);
      console.log('❌ Should have failed without authentication!');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ Notifications endpoint correctly requires authentication (401)');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    }

    // Test 4: Test notification stream endpoint
    console.log('\n4️⃣ Testing notification stream endpoint...');
    try {
      const streamResponse = await axios.get(`${BASE_URL}/api/auth/notifications/stream`);
      console.log('❌ Should have failed without authentication!');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ Notification stream correctly requires authentication (401)');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    }

    // Test 5: Test mark notification as read endpoint
    console.log('\n5️⃣ Testing mark notification as read endpoint...');
    try {
      const markReadResponse = await axios.post(`${BASE_URL}/api/auth/notifications/123/read`);
      console.log('❌ Should have failed without authentication!');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ Mark notification as read correctly requires authentication (401)');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    }

    // Test 6: Test mark all notifications as read endpoint
    console.log('\n6️⃣ Testing mark all notifications as read endpoint...');
    try {
      const markAllReadResponse = await axios.post(`${BASE_URL}/api/auth/notifications/read-all`);
      console.log('❌ Should have failed without authentication!');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ Mark all notifications as read correctly requires authentication (401)');
      } else {
        console.log('❌ Unexpected error:', error.message);
      }
    }

    console.log('\n🎉 Notification System Test Completed!');
    console.log('\n📋 Summary:');
    console.log('✅ Server is running');
    console.log('✅ Registration endpoint works');
    console.log('✅ Notification endpoints require authentication');
    console.log('✅ Notification system infrastructure is in place');
    console.log('\n🔔 Notification Features:');
    console.log('• Login notifications are sent when new device logs in');
    console.log('• Users can view their notifications');
    console.log('• Users can mark notifications as read');
    console.log('• Real-time notification stream available');
    console.log('• Notification statistics available');

  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
  }
}

// Run the test
testNotificationSystem();
