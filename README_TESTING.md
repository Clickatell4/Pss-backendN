# PSS Backend - Testing Branch

This branch is dedicated to testing and QA environments deployed on Render.

## Deployment Information

- **Environment**: Testing/Staging
- **Base URL**: https://pss-backend-testing.onrender.com
- **Database**: Supabase PostgreSQL (Session Pooler)
- **Branch**: `testing`
- **Auto-Deploy**: Enabled

## What's Different from Main?

The `testing` branch is deployed to a separate Render service that:
- Uses the same codebase as `main`
- Connects to a dedicated test database
- Allows testing changes before merging to production
- Can be updated independently from the production environment

## Testing Documentation

Comprehensive testing documentation is available in the `/docs/confluence/` directory:

### Quick Links

1. **[Quick Start Guide](docs/confluence/quick-start.md)** - Get started in 5 minutes
2. **[Environment Setup](docs/confluence/environment-setup.md)** - Configure your testing environment
3. **[Authentication Guide](docs/confluence/authentication.md)** - JWT, 2FA, and session management
4. **[API Reference](docs/confluence/api-reference.md)** - Complete endpoint documentation
5. **[Postman Guide](docs/confluence/postman-guide.md)** - Testing with Postman
6. **[cURL Guide](docs/confluence/curl-guide.md)** - Testing with cURL commands
7. **[Python Guide](docs/confluence/python-guide.md)** - Testing with Python requests
8. **[Browser Testing](docs/confluence/browser-testing.md)** - Browser-based testing
9. **[Test Scenarios](docs/confluence/test-scenarios.md)** - Complete user journeys
10. **[Security Testing](docs/confluence/security-testing.md)** - Security test checklists
11. **[Troubleshooting](docs/confluence/troubleshooting.md)** - Common issues and solutions

### Postman Collection

A complete Postman collection with 70+ endpoints is available:
- **File**: `/postman/PSS_Backend_Testing.postman_collection.json`
- **Test Data**: `/postman/test_data.json`
- **Documentation**: `/postman/README.md`

Import the collection into Postman to start testing immediately!

## How to Use This Branch

### For Developers

1. **Create feature branch from testing**:
   ```bash
   git checkout testing
   git pull origin testing
   git checkout -b feature/your-feature
   ```

2. **Make changes and test locally**

3. **Push to testing for deployment**:
   ```bash
   git checkout testing
   git merge feature/your-feature
   git push origin testing
   ```

4. **Verify deployment** at https://pss-backend-testing.onrender.com

5. **Merge to main** when ready for production

### For QA/Testers

1. **Import Postman collection** from `/postman/PSS_Backend_Testing.postman_collection.json`
2. **Follow Quick Start Guide** in docs/confluence/quick-start.md
3. **Run test scenarios** documented in docs/confluence/test-scenarios.md
4. **Report issues** via GitHub Issues or your project management tool

## Current Deployment Status

Check the deployment status at: https://dashboard.render.com

## Support

For questions or issues with the testing environment:
- Check the [Troubleshooting Guide](docs/confluence/troubleshooting.md)
- Contact the development team
- Create an issue on GitHub

---

**Last Updated**: 2025-12-31
**Maintained By**: PSS Backend Team
