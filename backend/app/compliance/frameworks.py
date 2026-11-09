"""The control catalogue: seven frameworks, roughly a hundred controls.

The catalogue is curated rather than exhaustive. Every GDPR article and
every ISO 27001 clause is not listed -- that would bury the controls
that bear on stored data under ninety pages of governance clauses no
scan can speak to. What is listed is the set of controls a data scan has
something to say about, split into two kinds:

* **Verifiable controls.** The scanner can judge them. Either the data
  violates the requirement -- a card number stored in readable text, a
  verification value kept after authorisation -- or it does not.
* **Operational controls.** The scanner cannot judge them. Access
  reviews, audit trails, incident response, training. These are reported
  as ``REVIEW``, meaning *a human needs to check this*. They are never
  reported as ``PASS``, because a scanner that claims a passing audit
  control it cannot see is worse than one that says "check this".

The catalogue is a product artefact, not a legal opinion. Control
wording is a paraphrase for orientation; the authoritative text is the
regulation itself.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .models import Control, Framework

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "informational"


def _control(
    control_id: str,
    title: str,
    category: str,
    severity: str,
    description: str,
    remediation: str,
    triggers: Tuple[str, ...] = (),
    verifiable: bool = False,
) -> Control:
    return Control(
        id=control_id,
        title=title,
        category=category,
        severity=severity,
        description=description,
        remediation=remediation,
        triggers=triggers,
        verifiable=verifiable,
    )


# ---------------------------------------------------------------------------
# HIPAA -- 45 CFR Parts 160 and 164
# ---------------------------------------------------------------------------

HIPAA_CONTROLS: Tuple[Control, ...] = (
    _control(
        "164.308(a)(1)(ii)(A)",
        "Security management process",
        "Administrative Safeguards",
        HIGH,
        "Risk analysis and risk management must be implemented to safeguard "
        "electronic protected health information.",
        "Run and document a HIPAA security risk analysis covering the "
        "systems that hold ePHI, and track it to a remediation plan.",
    ),
    _control(
        "164.308(a)(3)(ii)(A)",
        "Information access management",
        "Administrative Safeguards",
        HIGH,
        "Policies and procedures must authorise access to ePHI for every "
        "person who needs it, and deny it for everyone else.",
        "Document access policies for the ePHI repositories identified by "
        "this scan and confirm each role has an approved access grant.",
    ),
    _control(
        "164.308(a)(3)(ii)(B)",
        "Access authorisation",
        "Administrative Safeguards",
        CRITICAL,
        "Access to ePHI must be authorised, and access granted for "
        "workforce members whose role justifies it.",
        "Review who can reach the patient data found by this scan and "
        "remove access that a role does not justify.",
    ),
    _control(
        "164.308(a)(4)(ii)(C)",
        "Access establishment and modification",
        "Administrative Safeguards",
        HIGH,
        "Access grants must be granted, modified and revoked as job "
        "responsibilities change.",
        "Establish a joiner-mover-leaver process tied to the ePHI systems "
        "listed in this report.",
    ),
    _control(
        "164.308(a)(5)(ii)(D)",
        "Password management",
        "Administrative Safeguards",
        MEDIUM,
        "Password procedures must be created and implemented for "
        "systems that hold ePHI.",
        "Apply the password standard to every system that exposes the "
        "health data found here.",
    ),
    _control(
        "164.308(a)(6)(ii)(D)",
        "Data backup and storage",
        "Administrative Safeguards",
        MEDIUM,
        "Backups of ePHI must be created, retained and disposed of "
        "securely.",
        "Confirm backups exist for the stores holding the health data "
        "found here, and that the backups are protected and encrypted.",
    ),
    _control(
        "164.308(a)(7)(ii)(A)",
        "Contingency plan: data backup",
        "Administrative Safeguards",
        MEDIUM,
        "An established disaster recovery plan must include the backup "
        "and recovery of ePHI.",
        "Test the recovery plan for the repositories that hold the "
        "health data found by this scan.",
    ),
    _control(
        "164.310(d)(1)",
        "Device and media controls",
        "Physical Safeguards",
        MEDIUM,
        "Hardware and media that hold ePHI must be controlled so that it "
        "cannot be used by unauthorised people.",
        "Inventory the devices and media that hold the data found here "
        "and record their disposal chain of custody.",
    ),
    _control(
        "164.310(d)(2)(i)",
        "Disposal",
        "Physical Safeguards",
        LOW,
        "Media holding ePHI must be disposed of so that the data cannot "
        "be read or reconstructed.",
        "Use a documented secure disposal process for any export or "
        "backup media derived from the stores found here.",
    ),
    _control(
        "164.312(a)(1)",
        "Access control",
        "Technical Safeguards",
        CRITICAL,
        "Technical policies must limit ePHI access to authorised persons.",
        "Restrict write and read access to the health data found by this "
        "scan to the roles that need it.",
    ),
    _control(
        "164.312(a)(2)(i)",
        "Unique user identification",
        "Technical Safeguards",
        HIGH,
        "Each person accessing ePHI must be uniquely identified.",
        "Confirm that access to the health data found here is via unique "
        "accounts, and that shared logins are not in use.",
    ),
    _control(
        "164.312(a)(2)(iv)",
        "Encryption and decryption of ePHI",
        "Technical Safeguards",
        HIGH,
        "A mechanism to encrypt and decrypt ePHI must be in place.",
        "Encrypt the health data found here at rest, and hold the keys "
        "outside the database where the data itself lives.",
    ),
    _control(
        "164.312(b)",
        "Audit controls",
        "Technical Safeguards",
        HIGH,
        "Systems holding ePHI must record and monitor activity.",
        "Enable audit logging for the repositories holding the health "
        "data found here and retain it for the required period.",
    ),
    _control(
        "164.312(c)(1)",
        "Integrity",
        "Technical Safeguards",
        MEDIUM,
        "ePHI must be protected from improper alteration or destruction.",
        "Enable integrity controls on the stores holding the health data "
        "found here.",
    ),
    _control(
        "164.312(e)(1)",
        "Transmission security",
        "Technical Safeguards",
        HIGH,
        "ePHI must be protected against unauthorised disclosure during "
        "transmission.",
        "Encrypt ePHI in transit and restrict the endpoints that may send "
        "or receive it.",
    ),
    _control(
        "164.314(a)",
        "Privacy Rule administrative safeguards",
        "Organizational Requirements",
        HIGH,
        "Administrative safeguards must be reasonably implemented to meet "
        "the Privacy Rule's conditions for uses and disclosures.",
        "Map the health data found here to the purposes it is used for "
        "and confirm a Privacy Rule safeguard exists for each.",
    ),
    _control(
        "164.502(b)",
        "Minimum necessary",
        "Privacy Rule",
        CRITICAL,
        "Uses and disclosures of ePHI must be limited to the minimum "
        "necessary to accomplish the purpose.",
        "Reduce the health data held per record to the fields the "
        "declared purpose actually needs, and drop the rest.",
        ("class:PHI",),
        True,
    ),
    _control(
        "164.514(a)",
        "De-identification standard",
        "Privacy Rule",
        CRITICAL,
        "Health information that is de-identified must meet the standard "
        "before it is disclosed or used.",
        "De-identify or reclassify the health data found here if it is "
        "used or disclosed outside the covered entity.",
        ("class:PHI",),
        True,
    ),
    _control(
        "164.514(b)",
        "Safe Harbor: removal of identifiers",
        "Privacy Rule",
        CRITICAL,
        "The eighteen Safe Harbor identifiers must be removed before "
        "health information is disclosed.",
        "Remove the medical record numbers, member identifiers, device "
        "identifiers and dates of birth found by this scan before any "
        "disclosure.",
        (
            "PHI_MEDICAL_RECORD_NUMBER",
            "PHI_HEALTH_PLAN_ID",
            "PHI_DEVICE_ID",
            "PHI_MEDICAL_LICENSE",
            "PHI_DATE_OF_BIRTH",
        ),
        True,
    ),
    _control(
        "164.524",
        "Uses and disclosures: authorisation",
        "Privacy Rule",
        MEDIUM,
        "A covered entity may not use or disclose ePHI without a valid "
        "authorisation or a permitted use.",
        "Confirm that each use of the health data found here rests on a "
        "documented authorisation or permitted use.",
    ),
    _control(
        "164.532",
        "Retention and disposal",
        "Privacy Rule",
        MEDIUM,
        "ePHI must be retained only as long as needed and disposed of "
        "securely afterwards.",
        "Set a retention period for the health data found here and "
        "automate its disposal.",
    ),
    _control(
        "164.400-406",
        "Breach notification",
        "Breach Notification Rule",
        HIGH,
        "A breach of unsecured ePHI must be reported to affected "
        "individuals and to the Secretary without unreasonable delay.",
        "Confirm that the health data found here is covered by a breach "
        "notification procedure and that the reporting timeline is "
        "understood.",
    ),
)


# ---------------------------------------------------------------------------
# PCI DSS v4.0
# ---------------------------------------------------------------------------

PCI_CONTROLS: Tuple[Control, ...] = (
    _control(
        "3.2.1",
        "Account data storage is kept to a minimum",
        "Requirement 3: Protect Stored Account Data",
        HIGH,
        "Account data must be stored only if the business need is "
        "justified.",
        "Justify or remove the cardholder data stored by the systems "
        "found in this scan.",
    ),
    _control(
        "3.3.1",
        "PAN is masked when displayed",
        "Requirement 3: Protect Stored Account Data",
        HIGH,
        "PAN must be masked when displayed so that only the first six and "
        "last four digits are visible.",
        "Mask the primary account numbers found by this scan everywhere "
        "they are shown to a person.",
    ),
    _control(
        "3.3.2",
        "PAN is masked when printed",
        "Requirement 3: Protect Stored Account Data",
        HIGH,
        "PAN must be masked when printed on a receipt or other paper "
        "record.",
        "Mask the primary account numbers found by this scan on printed "
        "output and on paper records.",
    ),
    _control(
        "3.3.3",
        "Sensitive authentication data is not retained",
        "Requirement 3: Protect Stored Account Data",
        CRITICAL,
        "The card verification code and full track data must not be "
        "retained after authorisation.",
        "Delete the card verification values found by this scan once "
        "authorisation completes, and stop persisting them at all.",
        ("PCI_CVV",),
        True,
    ),
    _control(
        "3.4.1",
        "PAN is rendered unreadable wherever it is stored",
        "Requirement 3: Protect Stored Account Data",
        CRITICAL,
        "PAN must be rendered unreadable using strong cryptography "
        "wherever it is stored.",
        "Tokenise or encrypt the primary account numbers found by this "
        "scan at rest, and keep the keys outside the database.",
        ("PCI_PAN",),
        True,
    ),
    _control(
        "3.5.1",
        "PAN is rendered unreadable",
        "Requirement 3: Protect Stored Account Data",
        CRITICAL,
        "PAN must be rendered unreadable wherever it is stored.",
        "Apply a rendering method -- truncation, index tokenisation, or "
        "strong cryptography -- to the card data found here.",
        ("PCI_PAN",),
        True,
    ),
    _control(
        "3.6.1",
        "Cryptographic keys are secured",
        "Requirement 3: Protect Stored Account Data",
        HIGH,
        "Keys used to protect stored account data must be secured.",
        "Store the encryption keys for the card data found here in a "
        "key management system, not alongside the data.",
    ),
    _control(
        "4.2.1",
        "Strong cryptography protects PAN in transit",
        "Requirement 4: Encrypt Data in Transit",
        HIGH,
        "PAN must be protected with strong cryptography whenever it is "
        "transmitted over an open, public network.",
        "Ensure the card data found here travels only over TLS 1.2 or "
        "later, with certificates validated.",
    ),
    _control(
        "6.3.3",
        "Payment page scripts are authorised",
        "Requirement 6: Develop and Maintain Secure Systems",
        HIGH,
        "Every script loaded on a consumer payment page must be "
        "authorised, integrity-checked and inventoried.",
        "Inventory and authorise the scripts used on the payment pages "
        "that handle the card data found here.",
    ),
    _control(
        "6.4.3",
        "Payment page scripts are managed",
        "Requirement 6: Develop and Maintain Secure Systems",
        MEDIUM,
        "An inventory of the scripts loaded on consumer payment pages must "
        "be maintained with written justification.",
        "Keep a written inventory and business justification for every "
        "script on the payment pages covering the data found here.",
    ),
    _control(
        "8.3.1",
        "Access to cardholder data is authenticated",
        "Requirement 8: Identify Users and Authenticate Access",
        HIGH,
        "All access to cardholder data must be authenticated.",
        "Require authentication for every path that reaches the card data "
        "found by this scan.",
    ),
    _control(
        "8.3.6",
        "Passwords meet minimum complexity",
        "Requirement 8: Identify Users and Authenticate Access",
        MEDIUM,
        "User passwords must be at least twelve characters and pass the "
        "required complexity checks.",
        "Apply the password policy to the accounts that can reach the "
        "card data found here.",
    ),
    _control(
        "8.4.2",
        "Multi-factor authentication is used",
        "Requirement 8: Identify Users and Authenticate Access",
        HIGH,
        "Multi-factor authentication must be implemented for access to "
        "cardholder data.",
        "Enable multi-factor authentication for the administrative "
        "accounts that can read the card data found here.",
    ),
    _control(
        "10.2.1",
        "Audit logs are enabled and active",
        "Requirement 10: Log and Monitor All Access",
        HIGH,
        "Audit logs must be enabled and active for all system components "
        "that store or process cardholder data.",
        "Enable audit logging on the components that hold the card data "
        "found by this scan and confirm the logs are collected.",
    ),
    _control(
        "10.4.1",
        "Failures of critical security controls are logged",
        "Requirement 10: Log and Monitor All Access",
        MEDIUM,
        "Failures of critical security control systems must be logged and "
        "audited.",
        "Log and alert on failures of the controls protecting the card "
        "data found here.",
    ),
    _control(
        "12.3.1",
        "Targeted risk analyses are performed",
        "Requirement 12: Support Security with Policies",
        MEDIUM,
        "A targeted risk analysis must be performed for each system that "
        "stores cardholder data.",
        "Document a targeted risk analysis for the systems holding the "
        "card data found here.",
    ),
    _control(
        "12.10.1",
        "Incident response plan exists and is exercised",
        "Requirement 12: Support Security with Policies",
        HIGH,
        "An incident response plan must exist, be known to the workforce "
        "and be exercised.",
        "Confirm the incident response plan covers a breach of the "
        "stores holding the card data found here.",
    ),
)


# ---------------------------------------------------------------------------
# GDPR
# ---------------------------------------------------------------------------

GDPR_CONTROLS: Tuple[Control, ...] = (
    _control(
        "Art. 5(1)(c)",
        "Data minimisation",
        "Chapter II: Principles",
        HIGH,
        "Personal data must be adequate, relevant and limited to what is "
        "necessary for the purpose.",
        "Stop collecting and storing the high-sensitivity identifiers "
        "found by this scan unless each is necessary for a declared "
        "purpose.",
        ("AADHAAR", "PAN", "PHI_MEDICAL_RECORD_NUMBER", "PCI_CVV", "PCI_PAN"),
        True,
    ),
    _control(
        "Art. 5(1)(e)",
        "Storage limitation",
        "Chapter II: Principles",
        MEDIUM,
        "Personal data must be kept in a form that permits identification "
        "no longer than necessary.",
        "Set and enforce a retention period for the personal data found "
        "here, and delete it when the period ends.",
    ),
    _control(
        "Art. 5(1)(f)",
        "Integrity and confidentiality",
        "Chapter II: Principles",
        HIGH,
        "Personal data must be processed with appropriate security, "
        "including protection against unauthorised or unlawful processing.",
        "Apply encryption, access control and integrity protection to the "
        "personal data found by this scan.",
    ),
    _control(
        "Art. 6",
        "Lawfulness of processing",
        "Chapter II: Principles",
        HIGH,
        "Processing must have a lawful basis.",
        "Record a lawful basis for each processing activity that touches "
        "the personal data found here.",
    ),
    _control(
        "Art. 9(1)",
        "Special categories of personal data",
        "Chapter II: Principles",
        CRITICAL,
        "Health data may not be processed unless an Article 9(2) "
        "condition applies.",
        "Establish and record the Article 9(2) condition that licenses "
        "processing the health data found by this scan, or stop "
        "processing it.",
        ("class:PHI",),
        True,
    ),
    _control(
        "Art. 9(2)",
        "Safeguards for special category data",
        "Chapter II: Principles",
        HIGH,
        "Processing of special category data must be subject to "
        "appropriate safeguards.",
        "Apply the additional safeguards appropriate to the health data "
        "found here.",
    ),
    _control(
        "Art. 12-14",
        "Transparent information",
        "Chapter III: Rights of the Data Subject",
        MEDIUM,
        "Data subjects must be given clear information about the "
        "processing and its purpose.",
        "Update the privacy notice to describe the processing of the "
        "data found by this scan.",
    ),
    _control(
        "Art. 15",
        "Right of access",
        "Chapter III: Rights of the Data Subject",
        MEDIUM,
        "Data subjects have the right to obtain confirmation of and access "
        "to their personal data.",
        "Make sure the personal data found here can be retrieved per "
        "subject, and that retrieval does not expose other subjects' "
        "data.",
    ),
    _control(
        "Art. 17",
        "Right to erasure",
        "Chapter III: Rights of the Data Subject",
        MEDIUM,
        "Data subjects have the right to have their personal data erased "
        "without undue delay in the listed circumstances.",
        "Provide an erasure path that reaches the personal data found by "
        "this scan, including in backups where the law requires it.",
    ),
    _control(
        "Art. 20",
        "Right to data portability",
        "Chapter III: Rights of the Data Subject",
        LOW,
        "Data subjects have the right to receive their personal data in "
        "a structured, commonly used, machine-readable format.",
        "Ensure the personal data found here can be exported per "
        "subject in a portable format.",
    ),
    _control(
        "Art. 25",
        "Data protection by design and by default",
        "Chapter II: Principles",
        CRITICAL,
        "Data protection measures must be designed into processing and "
        "applied by default.",
        "Apply privacy-by-design to the systems holding the regulated "
        "data found by this scan -- least privilege, pseudonymisation, "
        "and no raw identifiers by default.",
        ("class:PCI", "class:PHI"),
        True,
    ),
    _control(
        "Art. 28",
        "Processor obligations",
        "Chapter IV: Controller and Processor",
        MEDIUM,
        "Processing by a processor must be governed by a binding "
        "contract.",
        "Confirm that any processor with access to the data found here "
        "is bound by Article 28 terms.",
    ),
    _control(
        "Art. 30",
        "Records of processing activities",
        "Chapter IV: Controller and Processor",
        MEDIUM,
        "Controllers and processors must maintain a record of processing "
        "activities.",
        "Add the stores holding the personal data found here to the record "
        "of processing activities.",
    ),
    _control(
        "Art. 32",
        "Security of processing",
        "Chapter IV: Controller and Processor",
        CRITICAL,
        "Appropriate technical and organisational measures must be "
        "implemented, including encryption and pseudonymisation.",
        "Apply encryption, pseudonymisation and resilience measures to "
        "the personal data found by this scan.",
    ),
    _control(
        "Art. 33",
        "Notification of a personal data breach",
        "Chapter IV: Controller and Processor",
        HIGH,
        "A personal data breach must be notified to the supervisory "
        "authority within 72 hours where it is likely to result in risk.",
        "Confirm the stores holding the personal data found here are "
        "covered by the breach notification procedure.",
    ),
    _control(
        "Art. 35",
        "Data protection impact assessment",
        "Chapter IV: Controller and Processor",
        HIGH,
        "A DPIA is required where processing is likely to result in a "
        "high risk to data subjects.",
        "Complete a DPIA covering the health and cardholder data found by "
        "this scan.",
    ),
    _control(
        "Art. 44-49",
        "Transfers of personal data to third countries",
        "Chapter V: Transfers",
        MEDIUM,
        "Transfers of personal data outside the European Economic Area "
        "must have a valid legal mechanism.",
        "Identify where the personal data found here is replicated and "
        "confirm each location has a valid transfer mechanism.",
    ),
)


# ---------------------------------------------------------------------------
# DPDP Act, 2023 (India)
# ---------------------------------------------------------------------------

DPDP_CONTROLS: Tuple[Control, ...] = (
    _control(
        "Sec. 5",
        "Notice and lawful basis",
        "Chapter II: Processing of Personal Data",
        HIGH,
        "Personal data may only be processed for a lawful purpose, and "
        "the data principal must be given notice of the processing.",
        "Record the lawful purpose and issue the notice for the "
        "processing of the personal data found by this scan.",
    ),
    _control(
        "Sec. 6",
        "Purpose limitation",
        "Chapter II: Processing of Personal Data",
        MEDIUM,
        "Personal data must be used only for the purpose for which it was "
        "consented to.",
        "Confirm that each use of the personal data found here matches "
        "the purpose recorded for it.",
    ),
    _control(
        "Sec. 7",
        "Storage limitation",
        "Chapter II: Processing of Personal Data",
        MEDIUM,
        "Personal data must be kept only as long as reasonably necessary "
        "for the stated purpose.",
        "Apply a retention limit to the personal data found by this scan.",
    ),
    _control(
        "Sec. 8(5)",
        "Data security safeguards",
        "Chapter II: Processing of Personal Data",
        CRITICAL,
        "The data fiduciary must implement appropriate security "
        "safeguards to prevent personal data breaches.",
        "Apply access control, encryption and masking to the regulated "
        "data found by this scan.",
        ("class:PCI", "class:PHI"),
        True,
    ),
    _control(
        "Sec. 9",
        "Notification of personal data breach",
        "Chapter II: Processing of Personal Data",
        HIGH,
        "A personal data breach must be notified to the Board and to the "
        "affected data principals.",
        "Confirm the stores holding the personal data found here are "
        "covered by the breach notification procedure.",
    ),
    _control(
        "Sec. 11",
        "Right to erasure",
        "Chapter III: Rights of Data Principals",
        MEDIUM,
        "Data principals have the right to erasure of personal data and "
        "the right to withdraw consent.",
        "Provide an erasure path that reaches the personal data found by "
        "this scan.",
    ),
    _control(
        "Sec. 12",
        "Right to grievance redressal",
        "Chapter III: Rights of Data Principals",
        MEDIUM,
        "Data principals have the right to grievance redressal against "
        "the data fiduciary.",
        "Provide a grievance channel and confirm it can act on the "
        "personal data found here.",
    ),
    _control(
        "Sec. 13",
        "Obligations of the data fiduciary",
        "Chapter II: Processing of Personal Data",
        HIGH,
        "The data fiduciary is responsible for compliance, including "
        "oversight of processors.",
        "Confirm the processing of the personal data found here is "
        "governed by a named, accountable data fiduciary.",
    ),
    _control(
        "Sec. 14",
        "Processing of personal data of children",
        "Chapter II: Processing of Personal Data",
        MEDIUM,
        "Personal data of children must be processed with verifiable "
        "parental consent and the child's best interests in mind.",
        "Identify whether any of the personal data found here belongs to "
        "a child and, if so, record the parental consent.",
    ),
    _control(
        "Sec. 18",
        "Data protection impact assessment",
        "Chapter IV: Exemptions and Oversight",
        HIGH,
        "The Board may require a data protection impact assessment for "
        "processing that is likely to result in high risk.",
        "Complete an impact assessment covering the health and cardholder "
        "data found by this scan.",
    ),
    _control(
        "Sec. 33",
        "Exempted personal data",
        "Chapter IV: Exemptions and Oversight",
        INFO,
        "Certain categories of personal data are exempted from the "
        "provisions of the Act where they are in the public interest.",
        "Record the exemption relied on, if any, for the categories of "
        "data found by this scan.",
    ),
    _control(
        "Rule 4",
        "Consent manager notice",
        "The Digital Personal Data Protection Rules",
        MEDIUM,
        "A consent manager registered with the Board must display a "
        "notice of its name and the purposes of the consent it collects.",
        "Confirm that consent for the personal data found here is "
        "collected through a registered consent manager.",
    ),
)


# ---------------------------------------------------------------------------
# CCPA / CPRA
# ---------------------------------------------------------------------------

CCPA_CONTROLS: Tuple[Control, ...] = (
    _control(
        "Sec. 1798.100(a)",
        "Notice at collection",
        "Consumer Rights",
        HIGH,
        "A business must inform consumers of the categories of personal "
        "information collected and the purposes for collection.",
        "Update the notice at collection to describe the personal "
        "information found by this scan.",
    ),
    _control(
        "Sec. 1798.110",
        "Right to know",
        "Consumer Rights",
        MEDIUM,
        "A consumer has the right to request the categories and specific "
        "pieces of personal information collected about them.",
        "Ensure the personal information found here can be located per "
        "consumer on request.",
    ),
    _control(
        "Sec. 1798.105",
        "Right to delete",
        "Consumer Rights",
        MEDIUM,
        "A consumer has the right to request deletion of their personal "
        "information.",
        "Provide a deletion path that reaches the personal information "
        "found by this scan.",
    ),
    _control(
        "Sec. 1798.106",
        "Right to correct",
        "Consumer Rights",
        MEDIUM,
        "A consumer has the right to request correction of inaccurate "
        "personal information.",
        "Provide a correction path for the personal information found by "
        "this scan.",
    ),
    _control(
        "Sec. 1798.120",
        "Right to opt out of sale or sharing",
        "Consumer Rights",
        HIGH,
        "A consumer has the right to opt out of the sale or sharing of "
        "their personal information.",
        "Ensure the personal information found here is not sold or shared "
        "without a recorded opt-out.",
    ),
    _control(
        "Sec. 1798.121",
        "Right to limit use of sensitive personal information",
        "Consumer Rights",
        CRITICAL,
        "A consumer has the right to limit the use and disclosure of their "
        "sensitive personal information.",
        "Stop using and disclosing the sensitive personal information "
        "found by this scan -- government identifiers and card data with "
        "credentials -- unless the consumer has opted in.",
        ("AADHAAR", "PAN", "PCI_PAN", "PCI_CVV", "PHI_DATE_OF_BIRTH"),
        True,
    ),
    _control(
        "Sec. 1798.125",
        "Non-discrimination for exercising rights",
        "Consumer Rights",
        MEDIUM,
        "A business must not discriminate against a consumer for "
        "exercising their rights.",
        "Confirm that no decision rule touching the personal information "
        "found here penalises a consumer for exercising a right.",
    ),
    _control(
        "Sec. 1798.130",
        "Two or more designated methods",
        "Consumer Rights",
        MEDIUM,
        "A business must offer at least two methods for consumers to "
        "exercise their rights.",
        "Publish and support at least two methods for the requests that "
        "concern the personal information found here.",
    ),
    _control(
        "Sec. 1798.150",
        "Private right of action",
        "Consumer Rights",
        INFO,
        "Consumers may bring a statutory action for certain breaches of "
        "unreasonable security.",
        "Note that the personal information found here is within the "
        "scope of statutory damages for a breach of reasonable security.",
    ),
    _control(
        "CPRA Sec. 1798.140(ae)",
        "Sensitive personal information",
        "Definitions",
        CRITICAL,
        "Sensitive personal information includes government identifiers, "
        "financial account and card credentials, and health information.",
        "Treat the government identifiers, card credentials and health "
        "information found by this scan as sensitive personal information "
        "and apply the corresponding restrictions.",
        ("AADHAAR", "PAN", "PCI_PAN", "PCI_CVV"),
        True,
    ),
)


# ---------------------------------------------------------------------------
# SOC 2 -- Trust Services Criteria
# ---------------------------------------------------------------------------

SOC2_CONTROLS: Tuple[Control, ...] = (
    _control(
        "CC6.1",
        "Logical access security",
        "Logical and Physical Access Controls",
        HIGH,
        "The entity implements logical access security software, "
        "infrastructure and architectures over protected information "
        "assets.",
        "Restrict access to the regulated data found by this scan to "
        "authorised users and record the access controls applied.",
    ),
    _control(
        "CC6.2",
        "User registration and authorisation",
        "Logical and Physical Access Controls",
        HIGH,
        "Before issuing credentials, users are registered and authorised "
        "by an appropriate approver.",
        "Confirm that access to the data found here is granted through a "
        "registered and approved account request.",
    ),
    _control(
        "CC6.3",
        "Role-based access",
        "Logical and Physical Access Controls",
        MEDIUM,
        "Access to data and software is granted and modified by role, "
        "following segregation of duties.",
        "Apply role-based access to the regulated data found by this "
        "scan and keep segregation of duties intact.",
    ),
    _control(
        "CC6.6",
        "Boundary protection",
        "Logical and Physical Access Controls",
        HIGH,
        "External access points and managed interfaces are protected.",
        "Restrict the network paths into the systems holding the "
        "regulated data found here.",
    ),
    _control(
        "CC6.7",
        "Restriction of data transmission",
        "Logical and Physical Access Controls",
        MEDIUM,
        "Transmission, movement and removal of information is restricted "
        "to authorised users and processes.",
        "Restrict and log the movement of the regulated data found by "
        "this scan.",
    ),
    _control(
        "CC6.8",
        "Prevention of unauthorised software",
        "Logical and Physical Access Controls",
        LOW,
        "The entity prevents or detects unauthorised or malicious "
        "software.",
        "Confirm the systems holding the data found here are covered by "
        "the endpoint protection standard.",
    ),
    _control(
        "CC7.2",
        "Monitoring of system components",
        "System Operations",
        MEDIUM,
        "The entity monitors system components for anomalies indicative of "
        "malicious acts or errors.",
        "Monitor the systems holding the regulated data found by this "
        "scan and review the resulting alerts.",
    ),
    _control(
        "CC7.3",
        "Evaluation of security events",
        "System Operations",
        MEDIUM,
        "Security events are evaluated to determine whether they are "
        "incidents.",
        "Confirm that alerts on the stores holding the regulated data "
        "found here are triaged as security events.",
    ),
    _control(
        "CC7.4",
        "Incident response",
        "System Operations",
        HIGH,
        "The entity responds to identified security incidents by "
        "executing a defined incident response programme.",
        "Confirm the incident response programme covers the stores "
        "holding the regulated data found here.",
    ),
    _control(
        "CC8.1",
        "Change management",
        "Change Management",
        MEDIUM,
        "Changes to infrastructure, data, software and procedures are "
        "authorised, designed, developed, tested and approved.",
        "Route changes to the schemas holding the regulated data found "
        "here through the change management process.",
    ),
    _control(
        "A1.2",
        "Environmental protections",
        "Availability",
        LOW,
        "Physical and environmental protections are maintained against "
        "external and internal threats.",
        "Confirm the physical and environmental controls protecting the "
        "systems holding the data found here.",
    ),
    _control(
        "C1.1",
        "Identification and protection of confidential information",
        "Confidentiality",
        HIGH,
        "The entity identifies and maintains confidential information to "
        "meet its objectives.",
        "Classify the data found by this scan as confidential and apply "
        "the protection lifecycle that classification implies.",
    ),
    _control(
        "P4.2",
        "Disposal of customer information",
        "Privacy",
        MEDIUM,
        "The entity disposes of customer information to meet objectives "
        "and contractual commitments.",
        "Dispose of the customer data found by this scan in line with "
        "the retention schedule and any contractual commitments.",
    ),
)


# ---------------------------------------------------------------------------
# ISO/IEC 27001:2022 Annex A
# ---------------------------------------------------------------------------

ISO27001_CONTROLS: Tuple[Control, ...] = (
    _control(
        "A.5.9",
        "Inventory of information and associated assets",
        "Organizational Controls",
        MEDIUM,
        "An inventory of information and associated assets, including "
        "owners, is maintained.",
        "Add the stores holding the regulated data found by this scan to "
        "the information asset inventory with a named owner.",
    ),
    _control(
        "A.5.12",
        "Classification of information",
        "Organizational Controls",
        HIGH,
        "Information must be classified according to the information "
        "security needs of the organisation.",
        "Classify the regulated data found by this scan consistently with "
        "the organisation's classification scheme.",
    ),
    _control(
        "A.5.15",
        "Access control",
        "Organizational Controls",
        CRITICAL,
        "Rules to control physical and logical access to information must "
        "be established and implemented.",
        "Apply least-privilege access rules to the regulated data found "
        "by this scan.",
    ),
    _control(
        "A.5.16",
        "Identity management",
        "Organizational Controls",
        MEDIUM,
        "The full life cycle of identities is managed.",
        "Assign and maintain an identity owner for every account that can "
        "reach the data found here.",
    ),
    _control(
        "A.5.17",
        "Authentication information",
        "Organizational Controls",
        MEDIUM,
        "Allocation and management of authentication information is "
        "controlled by a management process.",
        "Control the allocation and rotation of credentials for the "
        "systems holding the data found here.",
    ),
    _control(
        "A.5.18",
        "Access rights",
        "Organizational Controls",
        HIGH,
        "Access rights to information and other assets are provisioned, "
        "reviewed, modified and removed as appropriate.",
        "Review the access rights granted on the regulated data found by "
        "this scan and remove the ones that are no longer needed.",
    ),
    _control(
        "A.5.24",
        "Information security incident management planning",
        "Organizational Controls",
        HIGH,
        "Information security incident management plans are established "
        "and implemented.",
        "Confirm the incident management plan covers the stores holding "
        "the regulated data found here.",
    ),
    _control(
        "A.5.31",
        "Legal, statutory, regulatory and contractual requirements",
        "Organizational Controls",
        HIGH,
        "Legal, statutory, regulatory and contractual requirements "
        "relevant to information are identified and addressed.",
        "Map the regulatory data found by this scan to the controls "
        "implementing the requirements that apply to it.",
    ),
    _control(
        "A.5.34",
        "Privacy and protection of PII",
        "Organizational Controls",
        HIGH,
        "The organisation must identify, analyse and address the privacy "
        "and protection needs of PII.",
        "Apply the organisation's PII protection rules to the regulated "
        "data found by this scan.",
    ),
    _control(
        "A.8.3",
        "Information access restriction",
        "Technological Controls",
        HIGH,
        "Access to information is restricted according to the established "
        "access control policy.",
        "Enforce the access control policy on the regulated data found by "
        "this scan.",
    ),
    _control(
        "A.8.5",
        "Secure authentication",
        "Technological Controls",
        MEDIUM,
        "Authentication technologies are used according to "
        "organisational authentication requirements.",
        "Require strong authentication for the accounts that reach the "
        "data found here.",
    ),
    _control(
        "A.8.10",
        "Information deletion",
        "Technological Controls",
        MEDIUM,
        "Information stored in information systems, devices or in any "
        "storage media is deleted when no longer required.",
        "Delete the regulated data found by this scan when its "
        "retention period ends, including from backups.",
    ),
    _control(
        "A.8.11",
        "Data masking",
        "Technological Controls",
        CRITICAL,
        "Data masking must be used in accordance with the organisation's "
        "classification scheme and business requirements.",
        "Mask the card data found by this scan wherever it is displayed, "
        "exported or logged.",
        ("PCI_PAN",),
        True,
    ),
    _control(
        "A.8.12",
        "Data leakage prevention",
        "Technological Controls",
        HIGH,
        "Data leakage prevention measures are applied to systems "
        "processing sensitive information.",
        "Apply data leakage prevention to the systems holding the "
        "regulated data found by this scan.",
    ),
    _control(
        "A.8.16",
        "Monitoring activities",
        "Technological Controls",
        MEDIUM,
        "Networks, systems and applications are monitored for anomalous "
        "behaviour and appropriate actions taken.",
        "Monitor the systems holding the regulated data found by this "
        "scan and act on the results.",
    ),
    _control(
        "A.8.24",
        "Use of cryptography",
        "Technological Controls",
        HIGH,
        "Rules for the effective use of cryptography, including key "
        "management, are defined and implemented.",
        "Apply the organisation's cryptography standard to the regulated "
        "data found by this scan.",
    ),
    _control(
        "A.8.26",
        "Application security requirements",
        "Technological Controls",
        MEDIUM,
        "Applications are protected against security vulnerabilities.",
        "Ensure the applications serving the data found here are patched "
        "and reviewed.",
    ),
    _control(
        "A.8.29",
        "Security testing in development and acceptance",
        "Technological Controls",
        LOW,
        "Security testing processes are established and implemented in "
        "the development life cycle.",
        "Include the stores holding the regulated data found here in the "
        "security testing scope.",
    ),
    _control(
        "A.8.33",
        "Test information protection",
        "Technological Controls",
        MEDIUM,
        "Test information is appropriately selected, protected and "
        "managed.",
        "Ensure test environments use synthetic data rather than copies "
        "of the regulated data found here.",
    ),
)


#: Every framework, keyed by its short name.
FRAMEWORKS: Dict[str, Framework] = {
    "HIPAA": Framework(
        key="HIPAA",
        name="HIPAA Security and Privacy Rules",
        version="45 CFR Parts 160 and 164",
        governs=("PHI",),
        always_applicable=False,
        controls=HIPAA_CONTROLS,
    ),
    "PCI_DSS": Framework(
        key="PCI_DSS",
        name="Payment Card Industry Data Security Standard",
        version="v4.0",
        governs=("PCI",),
        always_applicable=False,
        controls=PCI_CONTROLS,
    ),
    "GDPR": Framework(
        key="GDPR",
        name="General Data Protection Regulation",
        version="EU 2016/679",
        governs=("PII", "PHI", "PCI"),
        always_applicable=False,
        controls=GDPR_CONTROLS,
    ),
    "DPDP": Framework(
        key="DPDP",
        name="Digital Personal Data Protection Act",
        version="India, 2023",
        governs=("PII", "PHI", "PCI"),
        always_applicable=False,
        controls=DPDP_CONTROLS,
    ),
    "CCPA": Framework(
        key="CCPA",
        name="California Consumer Privacy Act as amended by the CPRA",
        version="Cal. Civ. Code 1798.100 et seq.",
        governs=("PII", "PCI"),
        always_applicable=False,
        controls=CCPA_CONTROLS,
    ),
    "SOC2": Framework(
        key="SOC2",
        name="SOC 2 Trust Services Criteria",
        version="2017 (rev. 2022)",
        governs=("PII", "PHI", "PCI"),
        always_applicable=True,
        controls=SOC2_CONTROLS,
    ),
    "ISO27001": Framework(
        key="ISO27001",
        name="ISO/IEC 27001 Information Security Management Systems",
        version="2022, Annex A",
        governs=("PII", "PHI", "PCI"),
        always_applicable=True,
        controls=ISO27001_CONTROLS,
    ),
}


def framework_summaries() -> List[Dict[str, object]]:
    """A short description of every framework, for the discovery endpoint."""
    return [
        {
            "key": key,
            "name": FRAMEWORKS[key].name,
            "version": FRAMEWORKS[key].version,
            "governs": list(FRAMEWORKS[key].governs),
            "always_applicable": FRAMEWORKS[key].always_applicable,
            "controls": FRAMEWORKS[key].control_count(),
        }
        for key in FRAMEWORKS
    ]


def total_control_count() -> int:
    return sum(framework.control_count() for framework in FRAMEWORKS.values())
