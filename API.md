# BreathGSLB API Documentation

This document explains how to set up and use the BreathGSLB API for managing DNS zones and user accounts with JWT authentication and secure API keys.

## Overview

The BreathGSLB API provides a RESTful interface for managing DNS zones, records, and user accounts with robust security features including:

- JWT-based authentication
- API key authentication
- Role-based access control
- Rate limiting
- Secure data encryption at rest
- GDPR compliance features
- Audit logging

## API Endpoints

### Authentication

#### POST /auth/token

Generate an authentication token for API access.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 86400
  }
}
```

### Zones

#### GET /zones

List all zones accessible to the authenticated user.

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "name": "example.com.",
      "type": "primary",
      "status": "active",
      "records": 5,
      "created_at": 1640995200
    }
  ]
}
```

#### POST /zones

Create a new zone.

**Request Body:**
```json
{
  "name": "example.com.",
  "ns": ["ns1.example.com.", "ns2.example.com."],
  "admin": "hostmaster.example.com.",
  "ttl_soa": 3600,
  "ttl_answer": 300,
  "refresh": 3600,
  "retry": 600,
  "expire": 1209600,
  "minttl": 300,
  "a_master": ["203.0.113.10"],
  "aaaa_master": ["2001:db8::10"]
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Zone created successfully",
  "data": {
    "zone": "example.com.",
    "timestamp": 1640995200
  }
}
```

#### GET /zones/{zone}

Retrieve details for a specific zone.

**Response:**
```json
{
  "status": "success",
  "data": {
    "name": "example.com.",
    "type": "primary",
    "status": "active",
    "ns": ["ns1.example.com.", "ns2.example.com."],
    "admin": "hostmaster.example.com.",
    "ttl_soa": 3600,
    "ttl_answer": 300,
    "refresh": 3600,
    "retry": 600,
    "expire": 1209600,
    "minttl": 300,
    "a_master": ["203.0.113.10"],
    "aaaa_master": ["2001:db8::10"],
    "created_at": 1640995200,
    "updated_at": 1640995200
  }
}
```

#### PUT /zones/{zone}

Update a zone.

**Request Body:**
```json
{
  "a_master": ["203.0.113.11"],
  "aaaa_master": ["2001:db8::11"]
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Zone example.com. updated successfully",
  "data": {
    "zone": "example.com.",
    "timestamp": 1640995200
  }
}
```

#### DELETE /zones/{zone}

Delete a zone.

**Response:**
```json
{
  "status": "success",
  "message": "Zone example.com. deleted successfully",
  "data": {
    "zone": "example.com.",
    "timestamp": 1640995200
  }
}
```

### Records

#### GET /zones/{zone}/records

List all records in a zone.

**Response:**
```json
{
  "status": "success",
  "data": {
    "zone": "example.com.",
    "records": [
      {
        "name": "@",
        "type": "A",
        "value": "203.0.113.10",
        "ttl": 300
      },
      {
        "name": "www",
        "type": "A",
        "value": "203.0.113.10",
        "ttl": 300
      }
    ]
  }
}
```

#### POST /zones/{zone}/records

Create a new record in a zone.

**Request Body:**
```json
{
  "name": "mail",
  "type": "A",
  "value": "203.0.113.20",
  "ttl": 300
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Record created in zone example.com. successfully",
  "data": {
    "zone": "example.com.",
    "record": "mail.example.com.",
    "type": "A",
    "value": "203.0.113.20",
    "timestamp": 1640995200
  }
}
```

#### PUT /zones/{zone}/records/{record}

Update a record in a zone.

**Request Body:**
```json
{
  "value": "203.0.113.21",
  "ttl": 600
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Record mail.example.com. in zone example.com. updated successfully",
  "data": {
    "zone": "example.com.",
    "record": "mail.example.com.",
    "timestamp": 1640995200
  }
}
```

#### DELETE /zones/{zone}/records/{record}

Delete a record from a zone.

**Response:**
```json
{
  "status": "success",
  "message": "Record mail.example.com. in zone example.com. deleted successfully",
  "data": {
    "zone": "example.com.",
    "record": "mail.example.com.",
    "timestamp": 1640995200
  }
}
```

### Users (Manager Only)

#### GET /users

List all user accounts.

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "uuid": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "is_active": true,
      "created_at": 1640995200,
      "limits": {
        "max_zones": 1,
        "max_records": 100
      }
    }
  ]
}
```

#### POST /users

Create a new user account.

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "password": "password123",
  "limits": {
    "max_zones": 3,
    "max_records": 500
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "User account created successfully",
  "data": {
    "user": {
      "uuid": "123e4567-e89b-12d3-a456-426614174001",
      "email": "newuser@example.com",
      "is_active": true,
      "created_at": 1640995200
    },
    "api_key": "sk_live_abcdefghijklmnopqrstuvwxyz123456",
    "limits": {
      "max_zones": 3,
      "max_records": 500
    }
  }
}
```

#### GET /users/{user}

Retrieve details for a specific user account.

**Response:**
```json
{
  "status": "success",
  "data": {
    "uuid": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "is_active": true,
    "created_at": 1640995200,
    "limits": {
      "max_zones": 1,
      "max_records": 100
    }
  }
}
```

#### PUT /users/{user}

Update a user account.

**Request Body:**
```json
{
  "is_active": false,
  "limits": {
    "max_zones": 0,
    "max_records": 0
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "User account 123e4567-e89b-12d3-a456-426614174000 updated successfully",
  "data": {
    "user": {
      "uuid": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "is_active": false,
      "created_at": 1640995200,
      "updated_at": 1640995200
    }
  }
}
```

#### DELETE /users/{user}

Delete a user account.

**Response:**
```json
{
  "status": "success",
  "message": "User account 123e4567-e89b-12d3-a456-426614174000 deleted successfully",
  "data": {
    "user": "123e4567-e89b-12d3-a456-426614174000",
    "timestamp": 1640995200
  }
}
```

### Statistics

#### GET /stats

Retrieve server statistics.

**Response:**
```json
{
  "status": "success",
  "data": {
    "zones": 2,
    "records": 150,
    "users": 10,
    "queries_per_second": 1250,
    "uptime": 86400,
    "timestamp": 1640995200
  }
}
```

### Health

#### GET /health

Check server health.

**Response:**
```json
{
  "status": "success",
  "data": {
    "healthy": true,
    "timestamp": 1640995200,
    "version": "1.0.0"
  }
}
```

## Authentication

### JWT Authentication

To authenticate using JWT, include the token in the Authorization header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key Authentication

To authenticate using an API key, include it in the Authorization header:

```
Authorization: ApiKey sk_live_abcdefghijklmnopqrstuvwxyz123456
```

## Security Features

### Rate Limiting

The API implements rate limiting to prevent abuse:
- Default: 100 requests per second per user
- Burst: 200 requests per second per user
- Window: 60 seconds

### Data Encryption

All sensitive data is encrypted at rest using AES-256 encryption.

### GDPR Compliance

The API includes GDPR compliance features:
- Data retention policies
- Right to erasure
- Data portability
- Audit logging

## Configuration

The API server is configured using the `api_config.yaml` file:

```yaml
# Manager user configuration
manager:
  uuid: "123e4567-e89b-12d3-a456-426614174000"
  email: "manager@example.com"

# API server settings
api:
  enabled: true
  listen: ":8443"
  cert_file: "/etc/breathgslb/api.crt"
  key_file: "/etc/breathgslb/api.key"
  token_file: "/etc/breathgslb/api.token"

# Default account limits
default_limits:
  max_zones: 1
  max_records: 100
  max_requests: 1000

# Security settings
security:
  jwt:
    algorithm: "HS256"
    expiration: 86400  # 24 hours
```

## Starting the API Server

To start the API server:

```bash
# Using default configuration
./breathgslb-api

# Using custom configuration
./breathgslb-api -config /path/to/api_config.yaml
```

## Manager Workflow

1. Shop user purchases a service
2. Manager authorizes the service
3. Manager creates a user account for the shop user
4. System generates API keys and sends them to the user
5. User uses API keys to manage their zones and records

## User Workflow

1. Receive API keys from manager
2. Use API keys to authenticate with the API
3. Create and manage zones and records
4. Monitor statistics and health