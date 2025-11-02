# API Key & Secret Documentation

## Overview

Your pharmacy management system now supports API key authentication for external applications to fetch data (sales, payments, branches, etc.) without requiring user login.

## Features

✅ **Secure API Key Management**
- Create, view, update, and delete API keys (Admin only)
- API secrets are hashed using bcrypt for security
- Track usage count and last used timestamp
- Optional expiration dates

✅ **Public API Endpoints**
- Access sales, payments, category payments, branches, categories, suppliers
- Dashboard summary endpoint with aggregated data
- All endpoints support filtering by date range, branch, category, etc.

## API Key Management (Admin Only)

### 1. Create API Key

**Endpoint:** `POST /api/api-keys`

**Headers:**
```
Authorization: Bearer <your_jwt_token>
Content-Type: application/json
```

**Body:**
```json
{
  "name": "External App",
  "description": "API key for mobile app integration",
  "expiresAt": "2025-12-31T23:59:59.000Z" // Optional
}
```

**Response:**
```json
{
  "id": "...",
  "name": "External App",
  "description": "API key for mobile app integration",
  "apiKey": "dw_1234567890_abc123",
  "apiSecret": "xyz789123456789def456",
  "isActive": true,
  "expiresAt": null,
  "createdAt": "2025-01-15T10:30:00.000Z",
  "warning": "⚠️ Save these credentials now! The API secret will not be shown again."
}
```

**⚠️ IMPORTANT:** Save both `apiKey` and `apiSecret` immediately! The secret will never be shown again.

### 2. List All API Keys

**Endpoint:** `GET /api/api-keys`

**Headers:**
```
Authorization: Bearer <your_jwt_token>
```

**Response:**
```json
[
  {
    "_id": "...",
    "name": "External App",
    "description": "API key for mobile app integration",
    "apiKey": "dw_1234567890_abc123",
    "isActive": true,
    "usageCount": 42,
    "lastUsed": "2025-01-15T14:30:00.000Z",
    "createdAt": "2025-01-15T10:30:00.000Z",
    "createdBy": {
      "_id": "...",
      "username": "admin",
      "fullName": "System Administrator"
    }
  }
]
```

### 3. Update API Key

**Endpoint:** `PUT /api/api-keys/:id`

**Headers:**
```
Authorization: Bearer <your_jwt_token>
Content-Type: application/json
```

**Body:**
```json
{
  "name": "Updated Name",
  "description": "Updated description",
  "isActive": false,
  "expiresAt": "2025-12-31T23:59:59.000Z"
}
```

### 4. Delete API Key

**Endpoint:** `DELETE /api/api-keys/:id`

**Headers:**
```
Authorization: Bearer <your_jwt_token>
```

### 5. Get API Key Usage Stats

**Endpoint:** `GET /api/api-keys/:id/stats`

**Headers:**
```
Authorization: Bearer <your_jwt_token>
```

**Response:**
```json
{
  "id": "...",
  "name": "External App",
  "usageCount": 42,
  "lastUsed": "2025-01-15T14:30:00.000Z",
  "createdAt": "2025-01-15T10:30:00.000Z",
  "isActive": true,
  "expiresAt": null
}
```

## Public API Endpoints (Use API Key Authentication)

All public API endpoints require authentication using API key and secret via headers or query parameters.

### Authentication Methods

**Option 1: Headers (Recommended)**
```
X-API-Key: dw_1234567890_abc123
X-API-Secret: xyz789123456789def456
```

**Option 2: Query Parameters**
```
?apiKey=dw_1234567890_abc123&apiSecret=xyz789123456789def456
```

### Available Endpoints

#### 1. Get All Sales

**Endpoint:** `GET /api/public/sales`

**Query Parameters:**
- `branchId` - Filter by branch ID
- `categoryId` - Filter by category ID
- `from` - Start date (ISO format)
- `to` - End date (ISO format)

**Example:**
```bash
curl -X GET "https://your-domain.com/api/public/sales?from=2025-01-01&to=2025-01-31" \
  -H "X-API-Key: dw_1234567890_abc123" \
  -H "X-API-Secret: xyz789123456789def456"
```

**Response:**
```json
{
  "success": true,
  "count": 150,
  "data": [
    {
      "_id": "...",
      "branchId": { "_id": "...", "name": "D WATSON PWD" },
      "categoryId": { "_id": "...", "name": "MEDICINE NEUTRA" },
      "date": "2025-01-15T10:30:00.000Z",
      "total": 5000,
      "profit": 1500,
      "items": [...]
    }
  ]
}
```

#### 2. Get All Payments

**Endpoint:** `GET /api/public/payments`

**Query Parameters:**
- `branchId` - Filter by branch ID
- `supplierId` - Filter by supplier ID
- `from` - Start date (ISO format)
- `to` - End date (ISO format)

**Example:**
```bash
curl -X GET "https://your-domain.com/api/public/payments" \
  -H "X-API-Key: dw_1234567890_abc123" \
  -H "X-API-Secret: xyz789123456789def456"
```

#### 3. Get All Category Payments

**Endpoint:** `GET /api/public/category-payments`

**Query Parameters:**
- `branchId` - Filter by branch ID
- `categoryId` - Filter by category ID
- `from` - Start date (ISO format)
- `to` - End date (ISO format)

#### 4. Get All Branches

**Endpoint:** `GET /api/public/branches`

**Example:**
```bash
curl -X GET "https://your-domain.com/api/public/branches" \
  -H "X-API-Key: dw_1234567890_abc123" \
  -H "X-API-Secret: xyz789123456789def456"
```

#### 5. Get All Categories

**Endpoint:** `GET /api/public/categories`

#### 6. Get All Suppliers

**Endpoint:** `GET /api/public/suppliers`

#### 7. Get Dashboard Summary

**Endpoint:** `GET /api/public/dashboard`

**Query Parameters:**
- `from` - Start date for calculations (ISO format)
- `to` - End date for calculations (ISO format)

**Response:**
```json
{
  "success": true,
  "data": {
    "summary": {
      "totalSales": 150000,
      "totalProfit": 45000,
      "monthlySales": 50000,
      "totalPayments": 30000,
      "totalCategoryPayments": 10000,
      "netAmount": 110000
    },
    "counts": {
      "branches": 7,
      "categories": 3,
      "suppliers": 10,
      "sales": 150,
      "payments": 25,
      "categoryPayments": 15
    }
  }
}
```

## JavaScript/Node.js Example

```javascript
const axios = require('axios');

const API_KEY = 'dw_1234567890_abc123';
const API_SECRET = 'xyz789123456789def456';
const BASE_URL = 'https://your-domain.com';

async function fetchSales() {
  try {
    const response = await axios.get(`${BASE_URL}/api/public/sales`, {
      headers: {
        'X-API-Key': API_KEY,
        'X-API-Secret': API_SECRET
      },
      params: {
        from: '2025-01-01',
        to: '2025-01-31'
      }
    });
    
    console.log('Sales:', response.data.data);
    console.log('Total Count:', response.data.count);
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

// Fetch dashboard summary
async function fetchDashboard() {
  try {
    const response = await axios.get(`${BASE_URL}/api/public/dashboard`, {
      headers: {
        'X-API-Key': API_KEY,
        'X-API-Secret': API_SECRET
      }
    });
    
    console.log('Dashboard Summary:', response.data.data.summary);
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

fetchSales();
fetchDashboard();
```

## Python Example

```python
import requests

API_KEY = 'dw_1234567890_abc123'
API_SECRET = 'xyz789123456789def456'
BASE_URL = 'https://your-domain.com'

headers = {
    'X-API-Key': API_KEY,
    'X-API-Secret': API_SECRET
}

# Fetch sales
response = requests.get(
    f'{BASE_URL}/api/public/sales',
    headers=headers,
    params={'from': '2025-01-01', 'to': '2025-01-31'}
)

if response.status_code == 200:
    data = response.json()
    print(f"Total Sales: {data['count']}")
    print(f"Sales Data: {data['data']}")
else:
    print(f"Error: {response.status_code} - {response.text}")

# Fetch dashboard
response = requests.get(
    f'{BASE_URL}/api/public/dashboard',
    headers=headers
)

if response.status_code == 200:
    data = response.json()
    print(f"Total Sales: {data['data']['summary']['totalSales']}")
    print(f"Total Profit: {data['data']['summary']['totalProfit']}")
```

## Security Notes

1. **Never commit API keys/secrets to version control**
2. **Store credentials securely** - Use environment variables or secure vaults
3. **Rotate keys regularly** - Create new keys and delete old ones
4. **Use HTTPS** - Always use HTTPS in production to encrypt API requests
5. **Monitor usage** - Check usage stats regularly to detect unauthorized access
6. **Set expiration dates** - For temporary integrations, set expiration dates
7. **Disable unused keys** - Set `isActive: false` instead of deleting if you might need them again

## Error Responses

All endpoints return JSON error responses:

```json
{
  "error": "Invalid API key"
}
```

Common status codes:
- `401` - Authentication failed (invalid key/secret)
- `400` - Bad request (invalid parameters)
- `500` - Server error

## Need Help?

If you encounter any issues or have questions about the API, please contact the development team.

---

**Developed by MR Wasi**  
**D.Watson Pharmacy Management System**

