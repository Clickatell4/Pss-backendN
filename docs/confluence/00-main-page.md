# PSS Backend - Testing Guide

Comprehensive testing documentation for the PSS Backend API testing environment.

---

## Testing Environment

- **URL**: https://pss-backend-testing.onrender.com
- **Branch**: `testing`
- **Database**: Supabase PostgreSQL
- **Features**: 70+ API endpoints, JWT authentication, 2FA, session management

---

## Quick Links

| Page | Description |
|------|-------------|
| **[Quick Start Guide](./quick-start.md)** | Get started in 5 minutes |
| **[API Reference](./api-reference.md)** | Complete endpoint documentation (70+ endpoints) |
| **[Authentication Guide](./authentication.md)** | JWT, 2FA, sessions explained |
| **[Postman Guide](./postman-guide.md)** | Testing with Postman |
| **[cURL Guide](./curl-guide.md)** | Testing with cURL commands |
| **[Python Guide](./python-guide.md)** | Testing with Python requests |
| **[Test Scenarios](./test-scenarios.md)** | Complete user journeys |
| **[Security Testing](./security-testing.md)** | Security test checklist |
| **[Troubleshooting](./troubleshooting.md)** | Common issues and solutions |

---

## What You'll Find Here

### For QA Testers
- Ready-to-use Postman collection
- Test data samples
- Step-by-step test scenarios
- Expected results for all endpoints

### For Developers
- Complete API documentation
- Integration examples (Postman, cURL, Python, JavaScript)
- Error handling examples
- Security testing guidelines

### For Product Owners
- User journey documentation
- Feature coverage map
- Test completion checklists

---

## Getting Started

1. **[Import Postman Collection](./quick-start.md#step-1-import-postman-collection)**
   - Download from `/postman/PSS_Backend_Testing.postman_collection.json`
   - Import into Postman
   - Configure environment

2. **[Test Connection](./quick-start.md#step-3-test-connection)**
   - Health check endpoint
   - Verify API is accessible

3. **[Login](./quick-start.md#step-4-login)**
   - Get JWT tokens
   - Tokens auto-saved for subsequent requests

4. **[Run Test Scenarios](./test-scenarios.md)**
   - Follow complete user journeys
   - Test all major features

---

## Test Coverage

| Feature | Endpoints | Status |
|---------|-----------|--------|
| Authentication | 5 | ✅ Documented |
| Password Management | 4 | ✅ Documented |
| Two-Factor Auth (2FA) | 5 | ✅ Documented |
| Session Management | 5 | ✅ Documented |
| User Management | 5+ | ✅ Documented |
| Intake Form | 2 | ✅ Documented |
| Journal | 6 | ✅ Documented |
| Admin Notes | 4 | ✅ Documented |
| Dashboard | 2 | ✅ Documented |
| POPIA/GDPR | 6 | ✅ Documented |
| **Total** | **70+** | **100%** |

---

## Resources

### Repository Files
- Postman Collection: `/postman/PSS_Backend_Testing.postman_collection.json`
- Test Data: `/postman/test_data.json`
- Postman Guide: `/postman/README.md`
- Testing Branch README: `/README_TESTING.md`

### External Links
- Render Dashboard: https://dashboard.render.com
- Supabase Dashboard: https://supabase.com/dashboard
- GitHub Repository: https://github.com/Clickatell4/Pss-backendN/tree/testing

---

## Support

For questions or issues:
1. Check the [Troubleshooting Guide](./troubleshooting.md)
2. Contact the PSS Backend Team
3. Create an issue on GitHub

---

**Last Updated**: 2025-12-31  
**Maintained By**: PSS Backend Team  
**Version**: 1.0
