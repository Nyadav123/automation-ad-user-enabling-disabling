🔐 AD User Disable/Enable Automation

Purpose: Serverless automation to read employee exit/revoke lists from Google Sheets, save a copy to S3, and enable/disable users in Active Directory via LDAP (NTLM). Sends summary notifications via SNS.

📦 What you get in this repository

README.md (this file)

Ad.py — AD helper class (cleaned, commented, placeholders for sensitive values)

lambda_function.py — Lambda handler that reads sheets, calls AD code, stores spreadsheet to S3, and notifies via SNS (cleaned, commented, placeholders)

⚠️ Security & Sensitive Data

This repository must not contain secrets. All sensitive values (AD credentials, AWS resource names, Google tokens, bucket names, SNS Topic ARNs) have been removed and replaced with placeholders or environment / Secrets Manager references.

Before deploying, set values in one of the following safe ways:

AWS Secrets Manager (recommended) — use secret names/keys and grant least privilege to the Lambda execution role.

Lambda environment variables for non-critical configuration; do not store secrets in plaintext environment variables if avoidable.

Use IAM roles where possible (e.g., S3 access, SNS publish) instead of hard-coded keys.

🛠️ Prerequisites

Python 3.9+ (Lambda runtime compatibility)

ldap3 library (binary wheel recommended for Lambda; package into a Lambda layer). See [ldap3 docs].

boto3, requests, pandas, openpyxl (package these with your deployment or use layers)

AWS Lambda execution role with permissions for: secretsmanager:GetSecretValue, s3:PutObject, sns:Publish, logs:CreateLogGroup/PutLogEvents.

Google API credentials (client_id, client_secret, refresh_token) saved in Secrets Manager.

⚙️ Deployment notes

Create an AWS Secrets Manager secret for AD credentials and Google credentials. The code expects JSON keys — see the placeholder keys in the code.

Create an S3 bucket and SNS Topic. Provide ARNs/names in Secrets Manager or Lambda environment variables.

Package dependencies: bundle ldap3, pandas, openpyxl, requests into a Lambda layer or deployment package.

Deploy lambda_function.py as your Lambda handler with the correct handler path (e.g., lambda_function.lambda_handler).

🔧 How it works (high level)

Lambda invokes getExitStatusFrame() which reads two sheets (Exit and Revoked Resignation) from Google Sheets using a stored refresh token.

The latest unique rows per employee ID are computed; rows with invalid/unparseable dates are dropped and reported to SNS.

A spreadsheet snapshot is uploaded to S3 for audit.

For each ID, the AD helper (ADAP) binds to AD via NTLM over LDAPS (port 636) and sets userAccountControl bits to disable or enable accounts.

At the end a summary SNS message is published listing disabled, enabled and invalid IDs.
