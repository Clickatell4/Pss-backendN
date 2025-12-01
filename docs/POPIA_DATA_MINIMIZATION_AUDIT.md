# POPIA Data Minimization Audit Report
## SCRUM-118: UserProfile Field Analysis

**Audit Date:** December 1, 2025
**Audited By:** Backend Development Team
**Purpose:** POPIA Section 10 Compliance - Data Minimization Review
**Scope:** UserProfile model fields in `apps/users/models.py`

---

## Executive Summary

This audit reviews all UserProfile fields against POPIA Section 10 (Data Minimization) and Section 13 (Collection Limitation) requirements. We analyzed 17 fields across 5 categories: Identity, Contact, Medical, Emergency, and Accessibility.

**Key Findings:**
- ✅ **15 fields** are justified and necessary
- ⚠️ **1 field** is redundant (date_of_birth)
- ✅ **1 field** requires optional status (address - partial)

**Compliance Status:** 94% compliant with data minimization principles

---

## Audit Criteria

For each field, we evaluated:
1. **Purpose**: Why do we collect this?
2. **Legal Basis**: POPIA justification
3. **Necessity**: Could we operate without it?
4. **Risk**: What harm if breached?
5. **Decision**: Keep, Remove, Make Optional, or Defer

---

## Field-by-Field Analysis

### 1. IDENTITY FIELDS

#### 1.1 `id_number` (SA ID Number)
- **Type:** EncryptedCharField
- **Current Status:** Optional, Encrypted
- **Purpose:** Age verification, identity confirmation, program eligibility
- **Legal Basis:** POPIA Section 26 (Disability accommodation requires verification)
- **Necessity:** HIGH - Required for disability program participation
- **Contains:** DOB, gender, citizenship status
- **Risk:** CRITICAL - Identity theft, fraud
- **Retention:** 7 years post-graduation (compliance requirement)
- **Decision:** ✅ **KEEP** - Legally required, properly encrypted

**Justification:** SA ID verification is necessary for:
- Disability accommodation validation
- Age eligibility (program requirements)
- Government reporting compliance
- Insurance/liability purposes

---

#### 1.2 `date_of_birth`
- **Type:** DateField
- **Current Status:** Optional, **NOT** Encrypted
- **Purpose:** Age verification
- **Legal Basis:** Program eligibility
- **Necessity:** LOW - **Redundant** with id_number
- **Contains:** Date of birth
- **Risk:** MEDIUM - Age discrimination, privacy violation
- **Decision:** ⚠️ **REMOVE** - Redundant, can derive from ID number

**Justification for Removal:**
- SA ID number contains DOB (digits 1-6: YYMMDD)
- Storing separately creates unnecessary risk
- Can be calculated programmatically when needed
- Reduces PII surface area

**Implementation:**
```python
# Add property method to UserProfile
@property
def date_of_birth_calculated(self):
    """Calculate DOB from SA ID number."""
    if not self.id_number:
        return None

    # Extract YYMMDD from ID number
    yy = int(self.id_number[:2])
    mm = int(self.id_number[2:4])
    dd = int(self.id_number[4:6])

    # Determine century
    current_year = datetime.now().year % 100
    year = (1900 + yy) if yy > current_year else (2000 + yy)

    return date(year, mm, dd)
```

**Migration Required:** Remove `date_of_birth` field, add calculated property

---

### 2. CONTACT INFORMATION

#### 2.1 `contact_number`
- **Type:** CharField
- **Current Status:** Optional, **NOT** Encrypted
- **Purpose:** Program communication, emergency contact
- **Legal Basis:** Service delivery necessity
- **Necessity:** HIGH - Required for operational communication
- **Risk:** LOW-MEDIUM - Spam, harassment
- **Decision:** ✅ **KEEP** - Necessary for program operations

**Consideration:** Phone numbers are generally not considered highly sensitive PII, but we should consider:
- Rate-limiting outbound calls/SMS
- Opt-in for marketing communications
- Clear privacy policy about usage

---

#### 2.2 `address`
- **Type:** TextField
- **Current Status:** Optional, **NOT** Encrypted
- **Purpose:** Mailing correspondence, location-based support
- **Legal Basis:** Service delivery
- **Necessity:** MEDIUM - Useful but not always required
- **Risk:** MEDIUM - Physical location exposure
- **Decision:** ✅ **KEEP AS OPTIONAL** - Required for some services (mail, in-person support)

**Recommendation:**
- Keep as optional field
- Only request when necessary (e.g., need to mail documents)
- Consider splitting into structured fields (street, city, province, postal_code) for better privacy
- Consider allowing users to opt out of providing full address

---

### 3. EMERGENCY CONTACT INFORMATION

#### 3.1 `emergency_contact` (Name)
- **Type:** EncryptedCharField
- **Current Status:** Optional, Encrypted
- **Purpose:** Safety, medical emergencies
- **Legal Basis:** Duty of care, safety obligations
- **Necessity:** CRITICAL - Required for student safety
- **Risk:** HIGH - Privacy of third party
- **Decision:** ✅ **KEEP** - Safety requirement, properly encrypted

**Justification:**
- Educational institutions have duty of care
- Medical emergencies require quick contact
- Properly encrypted to protect third-party privacy

---

#### 3.2 `emergency_phone`
- **Type:** EncryptedCharField
- **Current Status:** Optional, Encrypted
- **Purpose:** Emergency contact in crisis situations
- **Legal Basis:** Duty of care, safety obligations
- **Necessity:** CRITICAL - Required for student safety
- **Risk:** HIGH - Third-party privacy
- **Decision:** ✅ **KEEP** - Safety requirement, properly encrypted

---

### 4. MEDICAL INFORMATION (All Encrypted)

#### 4.1 `diagnosis`
- **Type:** EncryptedTextField
- **Current Status:** Optional, Encrypted
- **Purpose:** Disability accommodation, support planning
- **Legal Basis:** POPIA Section 26 (Special Personal Information - Disability)
- **Necessity:** CRITICAL - Required for reasonable accommodation
- **Risk:** CRITICAL - Medical discrimination, stigma
- **Retention:** 7 years post-graduation
- **Decision:** ✅ **KEEP** - **Legally required** for disability support program

**POPIA Section 26 Compliance:**
- Required for providing reasonable accommodation
- Necessary for program customization
- User must consent (consent management implemented in SCRUM-11)
- Must be encrypted (already implemented in SCRUM-6)

---

#### 4.2 `medications`
- **Type:** EncryptedTextField
- **Current Status:** Optional, Encrypted
- **Purpose:** Safety, accommodation planning (e.g., medication breaks)
- **Legal Basis:** Duty of care, health & safety
- **Necessity:** HIGH - Important for safety and scheduling
- **Risk:** CRITICAL - Medical privacy, discrimination
- **Decision:** ✅ **KEEP** - Safety requirement, properly encrypted

**Justification:**
- Medication schedules may require accommodation
- Drug interactions awareness for campus health services
- Emergency medical treatment information

---

#### 4.3 `allergies`
- **Type:** EncryptedTextField
- **Current Status:** Optional, Encrypted
- **Purpose:** Safety, emergency preparedness
- **Legal Basis:** Duty of care, health & safety
- **Necessity:** CRITICAL - Life-saving information
- **Risk:** CRITICAL - Medical privacy
- **Decision:** ✅ **KEEP** - Safety requirement, properly encrypted

**Justification:**
- Severe allergies can be life-threatening
- Required for campus events (food service)
- Emergency medical treatment information

---

#### 4.4 `medical_notes`
- **Type:** EncryptedTextField
- **Current Status:** Optional, Encrypted
- **Purpose:** Additional medical context for support staff
- **Legal Basis:** Service customization
- **Necessity:** MEDIUM - Helpful but not always critical
- **Risk:** CRITICAL - Medical privacy, over-disclosure
- **Decision:** ✅ **KEEP AS OPTIONAL** - Useful for complex cases

**Recommendation:**
- Keep as optional
- Provide clear guidance on what should be included
- Regular review and cleanup of outdated notes
- Consider making user-editable

---

#### 4.5 `doctor_name`
- **Type:** EncryptedCharField
- **Current Status:** Optional, Encrypted
- **Purpose:** Medical verification, emergency contact
- **Legal Basis:** Service verification, emergency preparedness
- **Necessity:** MEDIUM - Useful for verification
- **Risk:** HIGH - Third-party medical provider privacy
- **Decision:** ✅ **KEEP AS OPTIONAL** - Useful but not critical

**Consideration:**
- Helpful for disability documentation verification
- Useful in medical emergencies
- Not always necessary (user may not want to disclose)

---

#### 4.6 `doctor_phone`
- **Type:** EncryptedCharField
- **Current Status:** Optional, Encrypted
- **Purpose:** Medical verification, emergency contact
- **Legal Basis:** Service verification, emergency preparedness
- **Necessity:** MEDIUM - Useful for verification
- **Risk:** HIGH - Third-party medical provider privacy
- **Decision:** ✅ **KEEP AS OPTIONAL** - Useful but not critical

---

### 5. ACCESSIBILITY & SUPPORT

#### 5.1 `accommodations`
- **Type:** TextField (NOT Encrypted)
- **Current Status:** Optional
- **Purpose:** Reasonable accommodation tracking
- **Legal Basis:** POPIA Section 26, disability rights
- **Necessity:** CRITICAL - Required for program delivery
- **Risk:** MEDIUM - Disability disclosure
- **Decision:** ✅ **KEEP** - Legally required for accommodation

**Consideration:** Should this be encrypted?
- **Current:** Not encrypted (operational necessity argument)
- **Recommendation:** Consider encrypting if it contains specific disability details
- **Alternative:** Keep high-level accommodations unencrypted (e.g., "extra time on tests"), encrypt detailed justifications

---

#### 5.2 `assistive_technology`
- **Type:** TextField (NOT Encrypted)
- **Current Status:** Optional
- **Purpose:** Technical support planning, equipment provision
- **Legal Basis:** Reasonable accommodation
- **Necessity:** HIGH - Required for technology support
- **Risk:** MEDIUM - Disability disclosure
- **Decision:** ✅ **KEEP** - Operational necessity

**Justification:**
- IT support needs to know what technology to support
- Equipment loan tracking
- Training needs assessment

---

#### 5.3 `learning_style`
- **Type:** CharField (NOT Encrypted)
- **Current Status:** Optional
- **Purpose:** Teaching customization
- **Legal Basis:** Service quality, educational outcomes
- **Necessity:** MEDIUM - Helpful for instruction
- **Risk:** LOW - Generally not sensitive
- **Decision:** ✅ **KEEP AS OPTIONAL** - Educational benefit

**Consideration:**
- Not disability-specific (many non-disabled students have learning preferences)
- Helps instructors customize teaching
- Low risk if breached

---

#### 5.4 `support_needs`
- **Type:** TextField (NOT Encrypted)
- **Current Status:** Optional
- **Purpose:** Holistic support planning
- **Legal Basis:** Service customization
- **Necessity:** HIGH - Important for program success
- **Risk:** MEDIUM - May contain sensitive information
- **Decision:** ✅ **KEEP** - Necessary for support services

**Consideration:** Should this be encrypted?
- May contain sensitive mental health or social information
- Recommendation: Encrypt or provide clear guidelines on what should be included

---

#### 5.5 `communication_preferences`
- **Type:** TextField (NOT Encrypted)
- **Current Status:** Optional
- **Purpose:** Service delivery optimization
- **Legal Basis:** Service quality
- **Necessity:** MEDIUM - Improves communication
- **Risk:** LOW - Generally not sensitive
- **Decision:** ✅ **KEEP AS OPTIONAL** - User experience benefit

**Examples:**
- Preferred communication channel (email, phone, SMS)
- Best time to contact
- Language preferences
- Accessibility needs (e.g., "use plain language")

---

## Summary of Decisions

| Field | Decision | Action Required |
|-------|----------|----------------|
| id_number | ✅ KEEP | None - properly encrypted |
| date_of_birth | ⚠️ REMOVE | Migration: Remove field, add calculated property |
| contact_number | ✅ KEEP | None - necessary for operations |
| address | ✅ KEEP (OPTIONAL) | Consider structured fields |
| emergency_contact | ✅ KEEP | None - properly encrypted |
| emergency_phone | ✅ KEEP | None - properly encrypted |
| diagnosis | ✅ KEEP | None - legally required, encrypted |
| medications | ✅ KEEP | None - safety requirement, encrypted |
| allergies | ✅ KEEP | None - life-safety requirement, encrypted |
| medical_notes | ✅ KEEP (OPTIONAL) | None - encrypted |
| doctor_name | ✅ KEEP (OPTIONAL) | None - encrypted |
| doctor_phone | ✅ KEEP (OPTIONAL) | None - encrypted |
| accommodations | ✅ KEEP | Consider encrypting |
| assistive_technology | ✅ KEEP | None |
| learning_style | ✅ KEEP (OPTIONAL) | None |
| support_needs | ✅ KEEP | Consider encrypting |
| communication_preferences | ✅ KEEP (OPTIONAL) | None |

---

## Recommendations

### Immediate Actions (High Priority)

1. **Remove `date_of_birth` field** ⚠️
   - Replace with calculated property from id_number
   - Create migration to remove field
   - Update serializers and views
   - **Effort:** 2-3 hours
   - **Risk Reduction:** Eliminates redundant PII storage

### Short-Term Actions (Medium Priority)

2. **Consider encrypting `accommodations` field**
   - If it contains specific disability details, encrypt it
   - Evaluate operational impact
   - **Effort:** 1-2 hours
   - **Risk Reduction:** Protects disability disclosure

3. **Consider encrypting `support_needs` field**
   - May contain sensitive mental health information
   - Evaluate what type of data is actually stored
   - **Effort:** 1-2 hours
   - **Risk Reduction:** Protects sensitive support information

4. **Structure `address` field**
   - Split into: street, city, province, postal_code
   - Allows partial collection (e.g., just city for statistics)
   - **Effort:** 4-5 hours (migration, serializers, views)
   - **Risk Reduction:** Reduces location precision

### Long-Term Actions (Low Priority)

5. **Implement field-level retention policies**
   - Some fields may have different retention requirements
   - Medical data: 7 years post-graduation
   - Contact data: Until account deletion
   - **Effort:** 1-2 days
   - **Compliance:** Full POPIA Section 14 compliance

6. **User-controlled field visibility**
   - Allow users to hide certain optional fields from staff
   - Implement "need-to-know" access controls
   - **Effort:** 3-4 days
   - **Privacy Enhancement:** User empowerment

---

## Privacy Policy Updates Required

After implementing field changes, update privacy policy to document:

1. **Purpose for each field**
   - Clear explanation of why we collect each piece of information
   - How it's used in the program

2. **Retention periods**
   - How long each type of data is kept
   - What happens after retention period

3. **Encryption practices**
   - Which fields are encrypted
   - Security measures in place

4. **User rights**
   - Right to access data
   - Right to request corrections
   - Right to request deletion (implemented in SCRUM-11)

---

## Data Retention Schedule

| Data Type | Retention Period | Legal Basis |
|-----------|------------------|-------------|
| Medical records | 7 years post-graduation | Healthcare records requirements |
| Emergency contacts | Duration of enrollment + 1 year | Duty of care |
| Contact information | Until account deletion | Service delivery |
| Accommodation records | 7 years post-graduation | Compliance documentation |
| Learning preferences | Duration of enrollment | Service quality |
| Audit logs | 2 years | POPIA Section 14 |

---

## POPIA Compliance Assessment

### Section 10: Data Minimization ✅
- **Status:** 94% Compliant
- **Issue:** `date_of_birth` is redundant
- **Action:** Remove redundant field
- **Timeline:** Next sprint

### Section 13: Collection Limitation ✅
- **Status:** Fully Compliant
- **Justification:** All fields have documented purpose
- **Collection:** Only at registration or when needed
- **Consent:** Implemented in SCRUM-11

### Section 14: Retention & Restriction ⚠️
- **Status:** Partially Compliant
- **Gap:** No automated retention enforcement
- **Action:** Implement retention cleanup (SCRUM-119)
- **Timeline:** Sprint N+1

---

## Conclusion

The UserProfile model is **94% compliant** with POPIA data minimization principles. Of 17 fields analyzed:
- **15 fields (88%)** are fully justified and properly protected
- **1 field (6%)** is redundant and should be removed
- **1 field (6%)** requires optional status consideration

### Key Strengths:
- ✅ Medical data properly encrypted
- ✅ Emergency contacts encrypted
- ✅ Clear purposes for all fields
- ✅ Consent management implemented (SCRUM-11)

### Areas for Improvement:
- ⚠️ Remove redundant `date_of_birth` field
- 🔍 Consider encrypting `accommodations` and `support_needs`
- 📊 Implement automated retention policies

**Overall Risk Assessment:** LOW
The system demonstrates strong data minimization practices with only minor improvements needed.

---

## Sign-Off

**Audit Completed:** December 1, 2025
**Next Review:** December 1, 2026 (Annual review)
**Approved By:** Backend Development Team
**POPIA Compliance Officer Review:** Pending

---

**Document Version:** 1.0
**Last Updated:** December 1, 2025
**Related Tickets:** SCRUM-6, SCRUM-8, SCRUM-11, SCRUM-118, SCRUM-119
