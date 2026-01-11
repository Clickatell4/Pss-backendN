# PSS Backend Documentation

Welcome to the **Personal Support System (PSS)** backend documentation! This guide will help the next development team understand, maintain, and complete this project.

## Project Status & Handover

**Date**: January 11, 2026
**Status**: In Development - Needs Completion
**Original Developer**: Tofiek Sasman
**Target Completion**: March 31, 2026

### What's Completed ✅

- Core Django REST API framework
- JWT-based authentication system
- User management (candidates, admins, superusers)
- Role-based access control
- Intake form processing
- Journal entries system
- Admin notes functionality
- Dashboard statistics API
- Basic POPIA compliance features
- Production deployment on Render
- Database connection fixes (pooler configuration)
- Django Axes brute-force protection

### What Needs Completion 🚧

See the [Project Handover Roadmap](./Handover-Roadmap.md) for the complete plan.

**Critical Issues**: 20 GitHub issues created (see Issues tab)
- 3 Epics (Security, Production Readiness, Testing)
- 5 Critical production features
- 4 Infrastructure & DevOps tasks
- 3 Performance & scalability features
- 4 Additional features & enhancements

## Quick Navigation

| Document | Description |
|----------|-------------|
| [Handover Roadmap](./Handover-Roadmap.md) | Complete project handover plan and priorities |
| [Architecture Overview](./Architecture.md) | System design, database models, API structure |
| [Development Setup](./Development-Setup.md) | Get your local environment running |
| [API Documentation](./API-Documentation.md) | Complete API endpoint reference |
| [Security & Compliance](./Security-Compliance.md) | POPIA requirements and security features |
| [Testing Guide](./Testing-Guide.md) | How to test the application |
| [Deployment Guide](./Deployment.md) | Production deployment instructions |

## About PSS Backend

The PSS Backend is a **Django REST Framework API** that powers the Personal Support System for CAPACITI students with disabilities. It provides:

- ✅ Secure JWT-based authentication
- ✅ Role-based access control (Candidate, Admin, Superuser)
- ✅ Medical and personal data management
- ✅ RESTful API endpoints
- ✅ POPIA (South African data protection) compliance features
- ✅ Comprehensive audit logging
- ⚠️ Data encryption for sensitive information (NEEDS IMPLEMENTATION)

## Key Technologies

| Technology | Version | Purpose |
|------------|---------|---------|
| **Django** | 4.2.7 | Web framework |
| **Django REST Framework** | 3.14.0 | API framework |
| **PostgreSQL** | 16+ (Neon) | Primary database |
| **SimpleJWT** | 5.3.0 | JWT authentication |
| **Gunicorn** | 21.2.0 | Production server |
| **Redis** | Latest | Caching & sessions (NEEDS SETUP) |
| **Celery** | Latest | Async tasks (NEEDS SETUP) |

## Repository Structure

```
Pss-backendN/
├── apps/                          # Django applications
│   ├── admin_notes/              # Admin notes on candidates
│   ├── authentication/           # JWT auth endpoints
│   ├── dashboard/                # Statistics & analytics
│   ├── intake/                   # Intake form processing
│   ├── journal/                  # Journal entries
│   └── users/                    # User & profile models
├── config/                       # Django project settings
│   ├── settings.py               # Main settings
│   ├── urls.py                   # URL routing
│   └── wsgi.py                   # WSGI config
├── docs/                         # This documentation
├── manage.py                     # Django management script
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment variables template
├── render.yaml                   # Render deployment config
└── README.md                     # Quick start guide
```

## Quick Start

### For New Team Members

1. **Start Here**: Read the [Development Setup](./Development-Setup.md) guide
2. **Understand the System**: Review the [Architecture Overview](./Architecture.md)
3. **Check the Plan**: Read the [Handover Roadmap](./Handover-Roadmap.md)
4. **Review Security**: Check [Security & Compliance](./Security-Compliance.md)
5. **Pick a Task**: Choose an issue from the [GitHub Issues](https://github.com/Clickatell4/Pss-backendN/issues)

### Prerequisites

```bash
- Python 3.11+
- PostgreSQL 16+ (or Neon serverless)
- Git
- Basic knowledge of Django and REST APIs
```

## Critical Security Notice

⚠️ **IMPORTANT**: This application handles sensitive data:

- Medical diagnoses and conditions
- Medications and allergies
- South African ID numbers (contains DOB, gender)
- Emergency contact information
- Disability accommodations

**Always**:
- Encrypt sensitive data at field level (SCRUM-6 - NOT YET IMPLEMENTED)
- Validate ALL user inputs
- Never log sensitive information
- Follow POPIA data protection guidelines
- Implement audit trails for all data access
- Test security features thoroughly

## Getting Help

### Resources

- **GitHub Issues**: [Project Issues](https://github.com/Clickatell4/Pss-backendN/issues)
- **Jira Board**: [SCRUM Project](https://capaciti-pss-team.atlassian.net/jira/software/projects/SCRUM/board)
- **Confluence Docs**: [Original Documentation](https://capaciti-pss-team.atlassian.net/wiki/spaces/SCRUM/pages/393219)
- **Frontend Repository**: [PSS-Frontend](https://github.com/Clickatell4/Pss-frontend)

### Common Issues

See [Development Setup](./Development-Setup.md) for troubleshooting:
- Database connection issues
- Migration errors
- Authentication problems
- Environment variable configuration

## Project Timeline

| Phase | Dates | Focus |
|-------|-------|-------|
| **Phase 1** | Jan 2026 | Critical security fixes & infrastructure |
| **Phase 2** | Feb 2026 | POPIA compliance & testing |
| **Phase 3** | Mar 2026 | Production deployment |

**Target Launch**: March 31, 2026

## Next Steps

👉 **New to the project?** Start with the [Handover Roadmap](./Handover-Roadmap.md)

👉 **Setting up locally?** Follow the [Development Setup](./Development-Setup.md)

👉 **Ready to code?** Pick an issue from [GitHub Issues](https://github.com/Clickatell4/Pss-backendN/issues)

---

**Last Updated**: January 11, 2026
**Status**: Handover Documentation
**Version**: 2.0
