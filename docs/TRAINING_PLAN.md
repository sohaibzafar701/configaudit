# Network Configuration Rule Tester (NCRT) - Training Plan

**Document Version:** 1.0  
**Date:** January 28, 2026  
**Target Audience:** End Users, Organization Administrators, System Administrators  
**Training Duration:** 2-3 Days (16-24 hours)

---

## Executive Summary

This training plan provides a structured approach to knowledge transfer for the Network Configuration Rule Tester (NCRT) platform. The plan covers all aspects of the system from basic usage to advanced customization, ensuring users can effectively utilize the platform for network device compliance auditing.

**Training Objectives:**
- Enable users to perform compliance audits on network devices
- Train administrators on system configuration and customization
- Ensure effective knowledge transfer for long-term system maintenance
- Provide hands-on experience with real-world scenarios

---

## Training Structure

### Day 1: Foundation and Core Operations (8 hours)
**Focus:** Basic system usage, audit creation, and report generation

### Day 2: Advanced Features and Administration (8 hours)
**Focus:** Rule management, baseline configurations, and customization

### Day 3: Administration and Troubleshooting (8 hours)
**Focus:** System administration, advanced customization, and support

---

## Day 1: Foundation and Core Operations

### Session 1: System Overview and Introduction (1.5 hours)

**Objectives:**
- Understand the purpose and capabilities of NCRT
- Navigate the user interface
- Understand multi-tenant architecture and organization context

**Topics:**
1. **Introduction to NCRT**
   - What is NCRT and its purpose
   - Key benefits and use cases
   - System architecture overview
   - Multi-tenant organization model

2. **User Interface Navigation**
   - Dashboard overview
   - Navigation menu and page structure
   - User roles and permissions
   - Organization context and switching

3. **System Access and Authentication**
   - User login and 2FA setup
   - Password management
   - Session management

**Hands-On Exercises:**
- Log in to the system
- Navigate through all main pages
- Explore dashboard widgets and statistics
- Review user profile and organization settings

**Materials:**
- System demo environment
- User guide: `docs/APPLICATION_DOCUMENTATION.md`
- Help page: `templates/help.html`

---

### Session 2: Creating and Managing Audits (2 hours)

**Objectives:**
- Upload network device configurations
- Create and execute compliance audits
- Monitor audit progress
- Understand audit results

**Topics:**
1. **Configuration Upload**
   - Supported file formats
   - Upload methods (file upload, paste text)
   - Configuration validation
   - Device metadata extraction

2. **Audit Creation**
   - Creating a new audit
   - Selecting audit parameters
   - Rule filtering and selection
   - Audit naming and organization

3. **Audit Execution**
   - Real-time progress monitoring
   - Audit status tracking
   - Error handling and troubleshooting
   - Audit completion notification

4. **Audit Results**
   - Understanding audit summary
   - Finding details and severity levels
   - Compliance scores by framework
   - Device metadata display

**Hands-On Exercises:**
- Upload sample Cisco router configuration
- Create an audit with default rules
- Monitor audit progress in real-time
- Review audit results and findings
- Upload configurations for different device types (switch, firewall)

**Materials:**
- Sample configuration files (provided)
- Test configurations: `testconfig/` directory
- Audit workflow documentation

---

### Session 3: Understanding Findings and Compliance (2 hours)

**Objectives:**
- Interpret audit findings
- Understand severity levels and risk scores
- Review compliance framework scores
- Navigate finding details

**Topics:**
1. **Finding Structure**
   - Parent and child findings
   - Finding categories
   - Severity levels (Critical, High, Medium, Low, Info)
   - Risk score calculation

2. **Compliance Frameworks**
   - ISO 27001 requirements
   - NIST Cybersecurity Framework
   - PCI-DSS compliance
   - CIS Benchmarks
   - HIPAA, SOX, GDPR

3. **Finding Details**
   - Config path references
   - Remediation guidance
   - Compliance requirement mappings
   - Finding context and evidence

4. **Finding Management**
   - Filtering findings by severity, category, rule
   - Sorting and grouping options
   - Finding search functionality
   - Remediation status tracking

**Hands-On Exercises:**
- Review findings from sample audit
- Filter findings by severity and category
- Examine finding details and remediation guidance
- Track remediation status for findings
- Review compliance scores by framework

**Materials:**
- Sample audit with various finding types
- Compliance framework reference guide
- Finding interpretation guide

---

### Session 4: Report Generation and Export (2 hours)

**Objectives:**
- Generate comprehensive compliance reports
- Export reports in multiple formats
- Customize report content
- Understand report sections

**Topics:**
1. **Report Types**
   - Executive Summary reports
   - Detailed Findings reports
   - Compliance-focused reports
   - Full comprehensive reports

2. **Report Formats**
   - PDF export (professional formatting)
   - HTML standalone reports
   - CSV exports for data analysis
   - JSON API responses

3. **Report Customization**
   - Section selection (statistics, findings, compliance, charts)
   - Filtering options
   - Sorting and grouping
   - Preset configurations

4. **Report Sections**
   - Executive summary
   - Statistics and charts
   - Detailed findings list
   - Compliance framework breakdowns
   - Remediation guidance

**Hands-On Exercises:**
- Generate PDF report for sample audit
- Create HTML standalone report
- Export CSV for data analysis
- Customize report sections and filters
- Generate executive summary report
- Export compliance-focused report

**Materials:**
- Sample reports (all formats)
- Report customization guide
- Report templates

---

### Day 1 Wrap-Up and Q&A (0.5 hours)

**Review:**
- Key concepts from Day 1
- Common questions and answers
- Preparation for Day 2

---

## Day 2: Advanced Features and Administration

### Session 5: Rule Management (2.5 hours)

**Objectives:**
- Understand rule types and structure
- Create and customize rules
- Manage rule lifecycle
- Test rules before deployment

**Topics:**
1. **Rule Types**
   - Pattern-based rules (regex matching)
   - Python-based rules (custom logic)
   - Hybrid rules (combination)

2. **Rule Structure**
   - Rule name and description
   - Category and severity
   - YAML content definition
   - Tags and vendor filtering
   - Compliance framework mappings
   - Remediation templates

3. **Rule Operations**
   - Creating new rules
   - Editing existing rules
   - Enabling/disabling rules
   - Deleting rules
   - Rule import/export

4. **Rule Testing**
   - Testing rules against sample configs
   - Validating rule logic
   - Rule debugging

5. **Organization-Specific Rules**
   - Platform rules vs organization rules
   - Copying platform rules
   - Customizing rules per organization

**Hands-On Exercises:**
- Create a pattern-based rule for SSH configuration
- Create a Python-based rule for password complexity
- Test rules against sample configurations
- Enable/disable rules and observe impact
- Import/export rule sets
- Copy and customize platform rules

**Materials:**
- Rule creation templates
- Sample rule definitions
- Rule testing guide
- YAML rule syntax reference

---

### Session 6: Baseline Configuration Management (2.5 hours)

**Objectives:**
- Understand baseline configurations
- Create and manage baselines
- Use platform baselines
- Compare audits against baselines

**Topics:**
1. **Baseline Concepts**
   - What are baseline configurations
   - Platform baselines vs organization baselines
   - Baseline structure and components

2. **Baseline Operations**
   - Viewing platform baselines
   - Copying platform baselines
   - Creating organization-specific baselines
   - Editing baseline configurations
   - Deleting baselines

3. **Baseline Components**
   - Baseline name and description
   - Vendor and device type selection
   - Compliance framework mapping
   - Rule selection and management
   - Template configurations

4. **Baseline Comparison**
   - Comparing audit results to baselines
   - Understanding compliance scores
   - Identifying gaps and deviations
   - Generating comparison reports

5. **Baseline Documentation**
   - Generating baseline documents
   - Exporting baseline templates
   - Baseline document formats (HTML, JSON, Text)

**Hands-On Exercises:**
- Browse platform baselines
- Copy a platform baseline for customization
- Create a new organization baseline
- Select rules for baseline
- Compare an audit against a baseline
- Generate baseline compliance report
- Export baseline document

**Materials:**
- Baseline examples
- Baseline creation guide
- Comparison report samples
- Baseline templates

---

### Session 7: Assets and Device Management (1.5 hours)

**Objectives:**
- Manage network devices as assets
- Track device audit history
- View device-specific compliance trends

**Topics:**
1. **Asset Management**
   - Device identification and metadata
   - Device grouping and organization
   - Asset lifecycle management

2. **Device Audit History**
   - Viewing all audits for a device
   - Comparing audits over time
   - Tracking compliance trends
   - Identifying configuration changes

3. **Device Metadata**
   - Hostname, model, firmware version
   - Vendor and device family
   - Location and organization assignment

**Hands-On Exercises:**
- View assets list
- Examine device audit history
- Compare multiple audits for same device
- Review device metadata
- Track compliance trends over time

**Materials:**
- Asset management guide
- Device tracking examples

---

### Session 8: Analysis and Comparison Features (1.5 hours)

**Objectives:**
- Compare multiple audits
- Analyze configuration differences
- Track compliance trends

**Topics:**
1. **Audit Comparison**
   - Selecting audits to compare
   - Viewing differences
   - Understanding comparison results

2. **Configuration Diff**
   - Side-by-side configuration comparison
   - Identifying changes
   - Impact analysis

3. **Trend Analysis**
   - Compliance score trends
   - Finding trends over time
   - Improvement tracking

**Hands-On Exercises:**
- Compare two audits for the same device
- Analyze configuration differences
- Review compliance trends
- Generate trend reports

**Materials:**
- Comparison examples
- Trend analysis guide

---

## Day 3: Administration and Troubleshooting

### Session 9: Organization Administration (2 hours)

**Objectives:**
- Manage organization settings
- Manage users and permissions
- Configure organization-specific rules

**Topics:**
1. **Organization Management**
   - Organization settings
   - Organization status and configuration
   - Multi-tenant isolation

2. **User Management**
   - Inviting users
   - User roles (Admin, User, Viewer)
   - User permissions and access control
   - User profile management

3. **Rule Assignment**
   - Assigning platform rules to organization
   - Managing organization-specific rules
   - Rule enable/disable per organization

**Hands-On Exercises:**
- Invite a new user to organization
- Assign user roles
- Configure organization settings
- Manage organization rules
- Test user permissions

**Materials:**
- Organization administration guide
- User management documentation
- Role and permission matrix

---

### Session 10: Advanced Customization (2 hours)

**Objectives:**
- Customize compliance frameworks
- Create custom rule categories
- Configure risk scoring
- Advanced rule development

**Topics:**
1. **Compliance Framework Customization**
   - Custom framework mappings
   - Requirement-level tracking
   - Framework-specific scoring

2. **Rule Customization**
   - Advanced YAML rule syntax
   - Python rule development
   - Custom remediation templates
   - Rule tagging strategies

3. **Risk Scoring**
   - Understanding risk weights
   - Customizing risk calculations
   - Prioritization strategies

4. **Integration Capabilities**
   - RESTful API usage
   - API authentication
   - Programmatic rule management
   - Automated audit creation

**Hands-On Exercises:**
- Create custom compliance framework mapping
- Develop advanced Python rule
- Customize risk scoring
- Use API for automated operations
- Create custom remediation templates

**Materials:**
- API documentation
- Advanced rule development guide
- Integration examples
- API reference guide

---

### Session 11: System Administration (2 hours)

**Objectives:**
- Understand system architecture
- Perform system maintenance
- Monitor system health
- Handle common issues

**Topics:**
1. **System Architecture**
   - Django application structure
   - Database schema
   - Static file management
   - Multi-tenant architecture

2. **System Maintenance**
   - Database backups
   - Log management
   - Performance optimization
   - Static file collection

3. **Monitoring and Health Checks**
   - System logs review
   - Error monitoring
   - Performance metrics
   - Audit processing status

4. **Platform Baseline Management**
   - Creating platform baselines
   - Updating platform baselines
   - Baseline auto-update mechanism
   - Manual baseline update command

**Hands-On Exercises:**
- Review system logs
- Perform database backup
- Collect static files
- Monitor audit processing
- Create platform baseline
- Update platform baselines

**Materials:**
- System administration guide
- Deployment documentation: `docs/DEPLOYMENT.md`
- Production setup guide: `docs/PRODUCTION_SETUP.md`
- Troubleshooting guide

---

### Session 12: Troubleshooting and Support (2 hours)

**Objectives:**
- Identify and resolve common issues
- Understand error messages
- Access support resources
- Escalate issues appropriately

**Topics:**
1. **Common Issues**
   - Configuration upload failures
   - Audit processing errors
   - Report generation issues
   - Rule execution problems

2. **Error Handling**
   - Understanding error messages
   - Log file analysis
   - Debugging techniques
   - Error reporting

3. **Support Resources**
   - Help documentation
   - FAQ section
   - Troubleshooting guides
   - Support contact information

4. **Best Practices**
   - Configuration file preparation
   - Audit naming conventions
   - Rule development best practices
   - Report customization tips

**Hands-On Exercises:**
- Troubleshoot sample error scenarios
- Analyze log files
- Use help documentation
- Practice error resolution
- Review troubleshooting scenarios

**Materials:**
- Troubleshooting guide
- FAQ document
- Common issues and solutions
- Support contact information

---

## Training Delivery Methods

### 1. Instructor-Led Training (Recommended)
- **Format:** Live sessions with hands-on exercises
- **Duration:** 2-3 days (16-24 hours)
- **Location:** On-site or virtual (video conference)
- **Materials:** Presentation slides, demo environment, exercise files

### 2. Self-Paced Training
- **Format:** Recorded sessions, documentation, and exercises
- **Duration:** Flexible (can be completed over 1-2 weeks)
- **Materials:** Video recordings, written guides, practice environment

### 3. Hybrid Approach
- **Format:** Combination of live sessions and self-paced modules
- **Duration:** 2-3 days with follow-up self-paced modules
- **Materials:** Live sessions for core topics, self-paced for advanced topics

---

## Training Materials and Resources

### Documentation
1. **Application Documentation** (`docs/APPLICATION_DOCUMENTATION.md`)
   - Comprehensive system documentation (1300+ lines)
   - API reference
   - Database schema
   - Workflow documentation

2. **Deployment Guide** (`docs/DEPLOYMENT.md`)
   - System deployment procedures
   - Configuration requirements
   - Environment setup

3. **Production Setup Guide** (`docs/PRODUCTION_SETUP.md`)
   - Production deployment steps
   - Security configuration
   - Performance optimization

4. **Help Page** (`templates/help.html`)
   - In-application help
   - Quick start guides
   - FAQs and troubleshooting

### Sample Files
- **Test Configurations** (`testconfig/` directory)
  - Sample Cisco router configurations
  - Sample switch configurations
  - Sample firewall configurations

- **Sample Reports**
  - PDF report examples
  - HTML report examples
  - CSV export examples

### Training Environment
- **Demo Instance:** Pre-configured system with sample data
- **Test Organization:** Dedicated organization for training exercises
- **Sample Audits:** Pre-created audits for demonstration

---

## Assessment and Evaluation

### Knowledge Checks
- **After Day 1:** Quiz on core operations (30 minutes)
- **After Day 2:** Practical exercise on rule and baseline management (1 hour)
- **After Day 3:** Troubleshooting scenario resolution (1 hour)

### Practical Exercises
- **Exercise 1:** Complete audit workflow (upload, audit, review, report)
- **Exercise 2:** Create and test custom rule
- **Exercise 3:** Create organization baseline and compare audit
- **Exercise 4:** Generate customized compliance report
- **Exercise 5:** Troubleshoot common issues

### Certification Criteria
- **Basic User:** Complete Day 1 training and pass knowledge check
- **Advanced User:** Complete Days 1-2 training and pass practical exercises
- **Administrator:** Complete all 3 days training and pass all assessments

---

## Training Schedule Options

### Option 1: Intensive 3-Day Training
- **Day 1:** 8 hours (Foundation)
- **Day 2:** 8 hours (Advanced Features)
- **Day 3:** 8 hours (Administration)
- **Total:** 24 hours

### Option 2: Extended 5-Day Training
- **Day 1:** 4 hours (Foundation Part 1)
- **Day 2:** 4 hours (Foundation Part 2)
- **Day 3:** 4 hours (Advanced Features Part 1)
- **Day 4:** 4 hours (Advanced Features Part 2)
- **Day 5:** 4 hours (Administration)
- **Total:** 20 hours

### Option 3: Modular Training (Recommended for Large Teams)
- **Module 1:** Basic Users (Day 1 only) - 8 hours
- **Module 2:** Advanced Users (Days 1-2) - 16 hours
- **Module 3:** Administrators (All 3 days) - 24 hours

---

## Post-Training Support

### Knowledge Transfer
- **Documentation Access:** Full access to all documentation
- **Help Resources:** In-application help and FAQs
- **Code Access:** Well-documented codebase for technical teams

### Ongoing Support
- **Q&A Sessions:** Scheduled follow-up sessions
- **Support Channels:** Email, ticketing system, or dedicated support portal
- **Community Forum:** Optional user community for knowledge sharing

### Training Feedback
- **Feedback Forms:** Post-training evaluation forms
- **Improvement Tracking:** Regular review of training effectiveness
- **Material Updates:** Continuous improvement based on feedback

---

## Training Prerequisites

### For End Users
- Basic understanding of network device configurations
- Familiarity with web applications
- Basic computer skills

### For Administrators
- Understanding of network security concepts
- Familiarity with compliance frameworks (helpful but not required)
- Basic system administration knowledge (for Day 3)

### Technical Requirements
- Access to training environment
- Web browser (Chrome, Firefox, Safari, or Edge)
- Internet connection
- Sample configuration files (provided)

---

## Training Feedback Collection

### Immediate Feedback
- **End of Each Day:** Daily feedback form
- **Topics Covered:** What was most/least useful
- **Pace Assessment:** Too fast, too slow, or just right
- **Clarity Rating:** Understanding of concepts

### Post-Training Evaluation
- **Overall Satisfaction:** Training quality rating
- **Knowledge Assessment:** Self-assessment of learning
- **Application Readiness:** Confidence in using the system
- **Improvement Suggestions:** Areas for enhancement

### Follow-Up Assessment
- **30 Days Post-Training:** Usage assessment
- **90 Days Post-Training:** Effectiveness evaluation
- **6 Months Post-Training:** Long-term knowledge retention

---

## Appendices

### Appendix A: Quick Reference Guide
- Common tasks and shortcuts
- Key concepts glossary
- Frequently used features

### Appendix B: Troubleshooting Quick Reference
- Common errors and solutions
- Support contact information
- Log file locations

### Appendix C: Sample Exercises
- Step-by-step exercise instructions
- Expected outcomes
- Solution guides

### Appendix D: Additional Resources
- External documentation links
- Compliance framework references
- Network security best practices

---

## Training Plan Maintenance

### Review Schedule
- **Quarterly Reviews:** Update training materials based on system updates
- **Annual Overhaul:** Comprehensive review and refresh of training content
- **Continuous Improvement:** Incorporate feedback and new features

### Version Control
- **Version Tracking:** Document changes and updates
- **Change Log:** Track modifications to training plan
- **Update Notifications:** Notify stakeholders of significant changes

---

**Document Owner:** Training Team  
**Last Updated:** January 28, 2026  
**Next Review:** April 28, 2026

---

## Contact Information

For questions about this training plan or to schedule training sessions, please contact:

**Training Coordinator:** [To be assigned]  
**Email:** [Training email]  
**Phone:** [Training phone]

**Technical Support:**  
**Email:** [Support email]  
**Documentation:** `docs/APPLICATION_DOCUMENTATION.md`
